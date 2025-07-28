import os
from typing import List, Dict, Optional
from sentence_transformers import SentenceTransformer

import chromadb
from chromadb.utils import embedding_functions
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_community.document_loaders import DirectoryLoader, UnstructuredMarkdownLoader
from sentence_transformers import CrossEncoder

from Misc.Logger import Logger

class ChromaConnector:
    def __init__(self, chroma_db_path: str = "./rag_store", data_store_path: str = "./data", embedding_model_name: str = "all-MiniLM-L6-v2", reranker_model_name = "cross-encoder/ms-marco-MiniLM-L-6-v2"):

        self.chroma_db_path = os.path.abspath(chroma_db_path)
        self.data_store_path = os.path.abspath(data_store_path)
        self.embedding_model_name = embedding_model_name
        self.reranker_model_name = reranker_model_name

        self.logger = Logger("~/novium/logs/chromadb/main.log", "chromadb")

        self.embedding_model = SentenceTransformer(self.embedding_model_name)
        self.embedding_function = embedding_functions.SentenceTransformerEmbeddingFunction(model_name=self.embedding_model_name)
        self.reranker = CrossEncoder(self.reranker_model_name)

        self.client = chromadb.PersistentClient(path=self.chroma_db_path)
        self.directory_loader = DirectoryLoader(path=self.data_store_path, glob="**/*.md", loader_cls=UnstructuredMarkdownLoader)
        self.collection = self.get_or_create_store()

    def get_or_create_store(self):
        try:
            self.collection = self.client.get_collection(
                name="dast_documentations",
                embedding_function=self.embedding_function
            )
            self.logger.info(f"Connected to existing ChromaDB store at '{self.chroma_db_path}'")
        except Exception:
            self.logger.warning(f"ChromaDB store not found at '{self.chroma_db_path}'. Creating a new one and loading documents from '{self.data_store_path}'")
            self.collection = self.client.create_collection(
                name="dast_documentations",
                embedding_function=self.embedding_function
            )
            self.load_documents()

        return self.collection

    def load_documents(self, chunk_size: int = 500, chunk_overlap: int = 50, batch_size: int = 32):
        documents = self.directory_loader.load()
        self.logger.info(f"Loaded {len(documents)} raw documents.")

        # Pre-process documents: parse metadata and assign IDs
        for document in documents:
            file_path = document.metadata.get("source", "unknown_path")
            file_basename = os.path.basename(file_path)
            metadata_from_filename = self._parse_filename(file_basename)

            # Update document metadata
            document.metadata["tool"] = metadata_from_filename.get("tool").title()
            document.metadata["title"] = metadata_from_filename.get("doc_type").title()
            document.id = file_path  # Assigning ID as per your original request

        text_splitter = RecursiveCharacterTextSplitter(
            chunk_size=chunk_size,
            chunk_overlap=chunk_overlap,
            length_function=len,  # Use standard Python len() for character count
            is_separator_regex=False,  # Use standard separators
        )

        langchain_chunks = []
        for doc in documents:
            chunks_for_doc = text_splitter.create_documents(
                texts=[doc.page_content],
                metadatas=[doc.metadata]  # Pass original metadata to be carried over
            )
            langchain_chunks.extend(chunks_for_doc)

        self.logger.info(f"Split raw documents into {len(langchain_chunks)} chunks using RecursiveCharacterTextSplitter.")

        if not langchain_chunks:
            self.logger.warning("No chunks generated from documents. Nothing to add.")
            return

        # Prepare all content, metadata, and IDs for batch processing
        all_chunk_contents = [chunk.page_content for chunk in langchain_chunks]
        all_chunk_metadatas = [chunk.metadata for chunk in langchain_chunks]

        # Generate unique IDs for each chunk. Using a combination of original doc ID and chunk index.
        all_chunk_ids = [
            f"{chunk.metadata.get('source', 'unknown_source')}_chunk_{i}"
            for i, chunk in enumerate(langchain_chunks)
        ]

        self.logger.info(f"Generating embeddings for all {len(all_chunk_contents)} chunks in batches...")

        # Batch embedding generation for performance
        all_embeddings = self.embedding_model.encode(all_chunk_contents, show_progress_bar=True).tolist()
        self.logger.info("All embeddings generated.")

        self.logger.info(f"Adding chunks to ChromaDB in batches of {batch_size}...")
        total_batches = (len(langchain_chunks) + batch_size - 1) // batch_size
        for i in range(0, len(langchain_chunks), batch_size):
            batch_ids = all_chunk_ids[i:i + batch_size]
            batch_documents = all_chunk_contents[i:i + batch_size]
            batch_metadatas = all_chunk_metadatas[i:i + batch_size]
            batch_embeddings = all_embeddings[i:i + batch_size]

            try:
                self.collection.add(
                    embeddings=batch_embeddings,
                    documents=batch_documents,
                    metadatas=batch_metadatas,
                    ids=batch_ids
                )
                self.logger.info(f"Successfully added batch {i // batch_size + 1}/{total_batches} ({len(batch_ids)} chunks).")
            except Exception as exception:
                self.logger.error(f"An unexpected error occurred while adding batch {i // batch_size + 1}", exception)
                break

        self.logger.info(f"Finished adding all {len(langchain_chunks)} chunks to ChromaDB.")

    def _parse_filename(self, filename: str) -> Dict[str, str]:
        metadata = {"tool": "Unknown", "doc_type": "Unknown"}

        try:
            name_without_ext = os.path.splitext(filename)[0]
            parts = name_without_ext.split("_")
            metadata["tool"] = parts[0].title()
            metadata["doc_type"] = parts[1].replace("-"," ").title()
        except Exception as exception:
            self.logger.warning(f"Could not parse filename. Returning metadata with 'unknown' for file '{filename}'", exception)

        return metadata

    def retrieve_relevant_documents(self, query: str, tool_name: Optional[str] = None, n_results: int = 10):
        try:
            where_clause = {}
            if tool_name:
                where_clause["tool"] = tool_name.title()
                print(f"Searching for relevant documents for {tool_name}")

            results = self.collection.query(
                query_texts=[query],
                n_results=n_results,
                include=['documents', 'distances', 'metadatas'],
                where=where_clause if where_clause else None
            )

            retrieved_documents = []

            for document, distance, metadata  in zip(results['documents'][0], results['distances'][0], results['metadatas'][0]):
                retrieved_documents.append({"document": document, "distance": distance, "metadata": metadata})

            reranked = self.rerank_documents(query, retrieved_documents)

            self.logger.info(f"Retrieved {len(retrieved_documents)} relevant documents for '{query[:25]}...'")

            return reranked
        except Exception as exception:
            self.logger.error("Error while retrieving relevant documents", exception)

        return []

    def rerank_documents(self, query: str, documents_info, top_n: int = 3) -> List[str]:
        if not documents_info:
            self.logger.warning("No documents to rerank.")
            return []

        try:
            pairs = [[query, doc_info['document']] for doc_info in documents_info]
            scores = self.reranker.predict(pairs)

            reranked_results_with_info = []
            for i, doc_info in enumerate(documents_info):
                document_info = {
                    'document': doc_info['document'],
                    'metadata': doc_info['metadata'],
                    'distance': doc_info['distance'],
                    'rerank_score': float(scores[i])
                }

                self.logger.info(f"Identified document '{doc_info['metadata']['source']}' matching query")

                reranked_results_with_info.append(document_info)
            
            reranked_results_with_info.sort(key=lambda x: x['rerank_score'], reverse=True)

            reranked_documents = []
            self.logger.info("Returning the following top documents after reranking:")

            for doc_info in reranked_results_with_info[:top_n]:

                # Safely get and log the source from metadata
                source = doc_info.get("metadata", {}).get("source", "Source not available")
                self.logger.info(f"- Source: {source}")
                self.logger.info(f"- Source: {doc_info['document']}")

                # Append the document content to the list for return
                reranked_documents.append(doc_info['document'])

            return reranked_documents

        except Exception as exception:
            self.logger.error(f"Could not retrieve reranked documents for query '{query}'", exception)
            return [doc_info['document'] for doc_info in documents_info]


