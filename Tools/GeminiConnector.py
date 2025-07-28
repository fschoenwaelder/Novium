import os
from typing import List, Optional
import re

from google import genai
from google.genai.types import GenerateContentConfig
from pydantic import BaseModel

from Misc.Logger import Logger
from Tools import ZapAdapter, NucleiAdapter
from Tools.ChromaConnector import ChromaConnector

class GeminiResponse(BaseModel):
    tool_name:str
    file_name:str
    template: object

class GeminiConnector:
    def __init__(self, generative_model_name: str = "gemini-2.0-flash", connect_with_chroma: bool = True):
        
        self.system_prompt = ""
        self.generation_config = None
        self.client = None
        self.google_api_key = os.getenv("GEMINI_API_KEY")
        self.generative_model_name = generative_model_name

        self.logger = Logger("~/novium/logs/gemini/main.log", "gemini")
        self.connect_with_chroma = connect_with_chroma

        if self.connect_with_chroma:
            self.chroma_connector = ChromaConnector()

    def set_system_prompt(self, tool=None, use_predefined=True, prompt = ""):
        if tool is None or use_predefined is False:
            self.system_prompt = prompt
            return

        if use_predefined:
            if tool == "zap":
                self.system_prompt = ZapAdapter.system_prompt

            if tool == "nuclei":
                self.system_prompt = NucleiAdapter.system_prompt
        else:
            self.system_prompt = prompt

    def setup_gemini(self, use_schema=True):
        self.client = genai.Client(api_key=self.google_api_key)

        schema = None
        mime_type = "text/plain"
        if use_schema:
            schema = list[GeminiResponse]
            mime_type = "application/json"

        self.generation_config = GenerateContentConfig(temperature=0, response_mime_type=mime_type, system_instruction=self.system_prompt, response_schema=schema)

    def generate_response(self, prompt: str, context_documents: List[str] = None) -> str:
        try:
            # Check if documents from RAG are given
            if context_documents:
                tool_docs_content = "\n".join(context_documents)
                prompt += f"\n**Relevant Tool Documentation (RAG):**\n{tool_docs_content}\n"

            self.logger.info(f"Sending query to {self.generative_model_name}")
            self.logger.info(f"Config: {self.generation_config}")
            self.logger.info(f"Query to {self.generative_model_name} with prompt:\n\n{prompt}")

            response = self.client.models.generate_content(contents=prompt, model=self.generative_model_name, config=self.generation_config)

            self.logger.info("Answer generated successfully.")
            return response.text
        except Exception as exception:
            self.logger.error(f"Error while generating the answer", exception=exception)
            return "Answer generation failed."

    def run_query(self, query: str, tool_name: Optional[str] = None, chroma_top_k: int = 10) -> str:

        # Check if chroma should be used
        if self.connect_with_chroma:
            relevant_data = re.findall(r"(?<=Identified Vulnerabilities & Attack Surface:)(.*)?(?=\*\*Instructions for Analysis)", query, re.DOTALL)
            self.logger.info(f"Extracted relevant data {relevant_data}")
            retrieved_docs = self.chroma_connector.retrieve_relevant_documents(query=relevant_data[0].strip(),tool_name=tool_name,n_results=chroma_top_k)
            return self.generate_response(query, retrieved_docs)

        return self.generate_response(prompt=query)