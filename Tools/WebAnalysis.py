import os
import sys
import time
import re

import requests

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import WebDriverException
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from Misc.Logger import Logger
from Tools.GeminiConnector import GeminiConnector

class WebAnalysis:
  
    def __init__(self, url):
        self.url = url
        self.gemini = GeminiConnector(connect_with_chroma=False)
        self.gemini.setup_gemini(use_schema=False)
        self.logger = Logger("~/novium/logs/WebAnalysis/main.log", "WebAnalysis")
        self.data = {
            "url": self.url,
            "headers": None,
            "cookies": None,
            "html_content": None,
            "server_banner": None
        }
        self.session_headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }

    def fetch_network_details(self):
        try:
            self.logger.info("+ Fetching HTTP headers and cookies...")
            response = requests.get(self.url, headers=self.session_headers, timeout=10, allow_redirects=True)
            response.raise_for_status()

            self.data["headers"] = dict(response.headers)
            self.data["cookies"] = response.cookies.get_dict()
            self.data["server_banner"] = self.data["headers"].get('Server', 'Not Found')

            self.logger.info(f"-> Server Banner: {self.data['server_banner']}")
            return True
        except requests.exceptions.RequestException as e:
            self.logger.error(f"!- Error fetching headers for {self.url}", e)
            return False

    def scrape_and_clean_html(self):
        try:
            self.logger.info("+ Scraping dynamically rendered HTML with headless Chrome...")

            user_data_dir = f"/tmp/chrome-user-data/{hash(time.time())}"
            os.makedirs(user_data_dir, exist_ok=True)

            chrome_options = Options()
            chrome_options.add_argument("--headless")
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")
            chrome_options.add_argument(f"--user-data-dir={user_data_dir}")
            chrome_options.add_argument(f"user-agent={self.session_headers['User-Agent']}")

            with webdriver.Chrome(options=chrome_options) as driver:
                driver.get(self.url)
                page_source = driver.page_source
            
            self.logger.info("-> HTML scraped. Now removing <style> and <img> tags...")

            soup = BeautifulSoup(page_source, 'lxml')
            for tag in soup(['style', 'img']):
                tag.decompose()

            internal_links = []
            for a_tag in soup.find_all('a', href=True):
                href = a_tag['href']

                # Same domain
                if href.startswith(self.url):
                    href = href[len(self.url):]
                    internal_links.append(href)
                    continue

                # Skipping links with protocol is specified
                if re.match(r'^[A-z]{1,5}://', href):
                    continue

                internal_links.append(href)

            self.data["internal_links"] = internal_links
            self.data["html_content"] = str(soup)

            self.logger.info("-> Successfully cleaned HTML.")
            return True
        except WebDriverException as e:
            self.logger.error("Selenium/WebDriver error", e)
            self.logger.error("Please ensure Google Chrome and ChromeDriver are installed.")
            return False
        except Exception as e:
            self.logger.error("An unexpected error occurred during scraping", e)
            return False

    def analyze(self):
        self.logger.info("+ Sending data to Gemini model for analysis...")

        self.gemini.set_system_prompt("You are a professional penetration tester and cybersecurity analyst. Provide a factual reconnaissance report based *only* on the data provided. Do not make any assumptions.")

        prompt = f"""
        Your task is to act as a cybersecurity analyst and generate a detailed reconnaissance report section based *only* on the provided "Collected Web Information" for the URL: {self.data['url']}.
        
        **Collected Web Information:**
        
        1.  **Server Banner:**
            {self.data.get('server_banner', 'N/A')}
        
        2.  **HTTP Headers:**
            {self.data.get('headers', 'N/A')}
        
        3.  **Cookies:**
            {self.data.get('cookies', 'N/A')}
        
        4.  **Internal Links:**
            {self.data.get('internal_links', 'N/A')}
        
        5.  **Cleaned Page HTML Content (first 4000 chars):**
            {self.data.get('html_content', 'N/A')[:4000]}
        
        ---
        
        **Reconnaissance Report Sections (Strictly based on 'Collected Web Information'):**
        
        Perform the following analysis and present the findings for each section clearly.
        
        0.  **Webpage Description and Application Identification:**
            -   Provide a concise description of the webpage's likely purpose (e.g., e-commerce shop, promotional site, blog, news portal, job board, personal portfolio, corporate website, forum, wiki). Base this *solely* on the provided HTML content and internal links.
            -   If, based on the **provided data and your pattern recognition knowledge**, you can identify the specific application or platform (e.g., WordPress, Joomla, Magento, Shopify, specific forum software), state its name.
            -   If you cannot identify the specific application/platform from the provided data, state that it is unknown.

        a.  **Technology Identification:**
            -   Identify the web server software and version if available.
            -   Identify backend languages/frameworks based on direct evidence from headers or cookies.
            -   Identify frontend libraries or frameworks based on direct evidence from the HTML.

        b.  **Security Header Analysis:**
            -   For each of the following security headers (`Content-Security-Policy`, `Strict-Transport-Security`, `X-Content-Type-Options`, `X-Frame-Options`, `Permissions-Policy`), state whether it is present or absent.
            -   If a header is present, validate its security configuration.
            -   Describe the *direct risks* associated with any missing headers.

        c.  **Cookie Analysis:**
            -   For each cookie, state which flags (`HttpOnly`, `Secure`, `SameSite`) are present or absent.
            -   Describe the *direct risks* associated with any missing flags for each cookie.
            -   Infer the purpose of cookies based *only* on their names.

        d.  **Link Analysis:**
            -   Provide a list of all unique in-scope URLs found (those on the same domain or starting with "/").
            -   Categorize these URLs based on their likely function or content (e.g., Login/Authentication, Registration/Account Creation, Password Reset, API Endpoints, Static Assets, Dynamic Content, Administrative Paths, Search Functionality, Contact/Support Pages, External Redirects if found within internal_links).
            -   Note any unusual or potentially sensitive file extensions or path segments (e.g., .git, .env, admin, backup, test, test.php, dev, configuration files, database files).
            -   Identify any links that appear to be broken or malformed based on their syntax.
            -   Highlight any links that suggest directory listings or unintended file exposure.

        e.  **Identified Vulnerabilities & Attack Surface:**
            -   **Strict Rule:** If software (server, framework, library) is identified, you **MUST only list known public vulnerabilities (CVEs) that directly apply to its *specific version***.
            -   If a software is identified but its version is *not* specified in the collected data, you **MUST state that the version is unknown and you MUST NOT list any potential CVEs or vulnerabilities for it.**
            -   Describe attack vectors that are *directly indicated* by the collected data (e.g., XSS due to a missing `Content-Security-Policy`, open redirects indicated by a URL pattern). Do not guess or infer attack vectors that are not explicitly supported by the provided evidence.
            -   List any interesting comments or unusual/sensitive paths visible *only* in the provided HTML.    

        **f. Retrieval Keywords for Tool Documentation (For RAG System Use):**
            -   *This section is an internal artifact for the RAG system to retrieve relevant tool documentation for ZAP and Nuclei.*
            -   *Based on the vulnerabilities, interesting paths, technologies, and attack vectors identified above (especially in section 'e'), generate a list of concise, technical keyword sets.*
            -   *Each bullet point should represent a distinct search query idea for relevant tool documentation.*
            -   *Do NOT include conversational language, explanations, or full sentences. Focus strictly on technical terms, vulnerability types, affected components, and detection methodologies relevant to penetration testing tools.*

        ---
        
        **IMPORTANT RULES TO FOLLOW FOR THIS REPORT SECTION:**
        1.  **NO ASSUMPTIONS:** Base your entire report *strictly* on the provided "Collected Web Information". Do not make any assumptions about technologies, configurations, or unseen data.
        2.  **VERSION-SPECIFIC VULNERABILITIES ONLY:** Only list potential CVEs if a specific version number for the software is identified in the "Collected Web Information". If no version is found, you must explicitly state that no vulnerabilities can be listed without a version.
        
        **Format your analysis for each section (0 to e) using clear, structured Markdown headings and bullet points.**
        """.strip()

        try:
            response = self.gemini.run_query(prompt)

            return response
        except Exception as e:
            message = "!- Failed to communicate with LLM"
            self.logger.error(message, e)
            return message

    def run(self):
        
        if not self.fetch_network_details() or not self.scrape_and_clean_html():
            sys.exit(1)

        analysis_report = self.analyze()

        self.logger.info(analysis_report)

        return analysis_report
