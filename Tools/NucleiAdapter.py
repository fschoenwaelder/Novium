from Tools.DastAdapter import DastAdapter
import subprocess
import os
import datetime
import json

from typing import Optional
from Misc.Logger import Logger

class NucleiAdapter(DastAdapter):

    # System prompt for LLm
    system_prompt = ("You are an expert cybersecurity automation engineer specializing in Nuclei. Your primary goal is to generate **multiple, fully functional, standalone YAML templates for Nuclei**, one for each distinct security vulnerability or flaw identified in the input. "
                    "\n"
                    "**Crucial Constraints for Template Generation:** "
                    "1.  **Self-Contained & Executable:** Each template must be immediately runnable without any external dependencies. Absolutely no placeholders (e.g., `[...]`, `YOUR_VALUE`), incomplete sections (e.g., `TODO`, `# Add logic here`), or references to external files. "
                    "2.  **Realistic Values:** Invent and use concrete, realistic values for all necessary fields (e.g., hostnames, paths, parameters, payloads) to ensure immediate and practical executability. "
                    "3.  **Inline Payloads:** All required payloads (e.g., lists of usernames, passwords, fuzzing strings, specific regex patterns) MUST be embedded directly within the YAML file using the inline list format. **DO NOT reference external payload files or variables.** "
                    "4.  **No Sample Templates:** You must **never** generate generic or sample templates. Every template must validate a real, specific security vulnerability or flaw. "
                    "5.  **Logical Filenames:** For each generated template, create a logical, lowercase, snake_case filename, clearly indicating the vulnerability it targets. Include the `.yaml` extension (e.g., `xss_reflected_dom.yaml`, `apache_cve_2022_xxxx.yaml`). "
                    "\n"
                    "**Guidance for Utilizing Provided Context (RAG) and Ensuring Template Quality:** "
                    "-  **Leverage Documentation for Matchers:** When designing the template logic, actively consult the provided Nuclei documentation (from the RAG system) for precise syntax, available options, and best practices for specific matcher types, protocols, or template structures. Apply this knowledge directly. "
                    "-  **Syntactical Correctness and Executability:** Before outputting, you **MUST** internally re-validate that each generated YAML template is syntactically correct and adheres to all Nuclei schema requirements. "
                    "-  **Vulnerability Detection & False Positive Reduction:** Each template **MUST** be designed to successfully detect its intended vulnerability when executed against a vulnerable target. Implement robust and specific matchers (and `matchers-condition: and` when appropriate) to **significantly reduce false positives**. Ensure the matchers are unique enough to identify the specific vulnerable response and discard responses from non-vulnerable or unrelated web servers. "
                    "-  **Detailed & Specific:** Templates should be as detailed and specific as possible for their target vulnerability. If the RAG provides information on common vulnerabilities or exploit patterns related to a request, integrate those patterns into the template's logic (e.g., specific HTTP methods, headers, body content, or paths). "
                    " "
                    "**Output Format - CRITICAL (Follow this exactly):** "
                    "Return **ONLY** a single JSON object. This JSON object must map **each generated filename** (as a string, including the `.yaml` extension) to its corresponding complete YAML template (as a single string, including all newlines and proper YAML indentation)."
                 ).strip()

    def __init__(self, target_url: str, report_dir: str = "~/novium/dast_reports/Nuclei",
                 log_dir: str = "~/novium/logs/Nuclei", templates: Optional[list[str]] = None):
        
        super().__init__(target_url=target_url, report_dir=report_dir, log_dir=log_dir)

        self.logger = Logger(f"{log_dir}/main.log", "Nuclei")
        
        # Use default templates if no template found
        self.templates = templates or ["misconfiguration", "cves", "vulnerabilities", "technologies"]

    def prepare_scan(self, **kwargs):
        try:
            # Check if Nuclei is available
            result = subprocess.run(["Nuclei", "-version"], check=True, capture_output=True, text=True)

            if result.stdout:
                self.logger.info(result.stdout)

            if result.stderr:
                self.logger.error(result.stderr)

        except (subprocess.CalledProcessError, FileNotFoundError) as exception:
            self.logger.error("Nuclei was not found.", exception)

    @staticmethod
    def save_template(filename, template, template_dir="~/novium/templates/Nuclei"):
        return DastAdapter.save_template(filename=filename, template=template, template_dir=template_dir)

    def run_scan(self, **kwargs) -> str:
        self.report_path = self.get_report_filename("Nuclei", "json")
    
        cmd_args = kwargs.get("cmd_args", [])
        cmd_override_args = kwargs.get("cmd_overide_args", False)

        command = [
            "Nuclei",
            "-u", self.target_url,  
            "-jsonl-export", self.report_path
        ]

        # Default args used for most scans
        default_args = [
            "-silent"          
        ]
        
        # Add template groups
        for template_group in self.templates:
            command.extend(["-t", template_group])

        # Add default args if override not set
        if not cmd_override_args:
            command.extend([*default_args])
        else:
            self.logger.warning(f"Warning: Override default commands with {cmd_args}")

        self.logger.info(f"Execute Nuclei command: {' '.join(command)}") 

        try:
            # Run Nuclei with generated templates
            result = subprocess.run(command, capture_output=True, text=True, check=False)

            self.logger.info(f"Executed scan at {datetime.datetime.now()} for target {self.target_url}")
            self.logger.info(f"Command: {' '.join(command)}")

            if result.stdout:
                self.logger.info(f"STDOUT: {result.stdout}")

            if result.returncode != 0:
                self.logger.warning(f"Nuclei finished with exit code {result.returncode}.")

            if result.stderr:
                self.logger.error(f"STDERR: {result.stderr}")

            self.logger.info("Nuclei scan executed successfully.")
            return self.report_path

        except FileNotFoundError as exception:
             self.logger.error("Nuclei command not found", exception)
             raise RuntimeError("Nuclei command not found.")
        except Exception as exception:
             self.logger.error("An unexpected error occurred.", exception)
             raise RuntimeError(f"An unexpected error occurred: {exception}")

    def parse_report(self, report_path: str) -> list[dict]:
        self.logger.info(f"Parse Nuclei json file: {report_path}")

        if not os.path.exists(report_path):
            self.logger.warning(f"Report file not found or empty at {report_path}.")
            return []

        findings_dict = {}
        with open(report_path, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    alert = json.loads(line)
                    name = alert.get('info', {}).get('name')
                    matched_at = alert.get('matched-at')

                    # Skip processing if the finding has no name
                    if not name:
                        continue

                    # If we haven't seen this finding name before, create a new entry for it.
                    if name not in findings_dict:
                        findings_dict[name] = {
                            'name': name,
                            'severity': alert.get('info', {}).get('severity'),

                            # Initialize 'matched_at' as an empty list
                            'matched_at': [],
                            'description': alert.get('info', {}).get('description'),
                            'tags': alert.get('info', {}).get('tags'),
                            'host': alert.get('host'),
                            'remediation': alert.get('info', {}).get('remediation'),
                            'curl_command': alert.get('curl-command')
                        }

                        self.logger.info(f"Identified the vulnerability {findings_dict[name]}")
                    
                    # Append the current 'matched_at' location to the list for this finding.
                    if matched_at:
                        findings_dict[name]['matched_at'].append(matched_at)


                except json.JSONDecodeError as exception:
                    self.logger.error(f"Error: Failed to parse JSON file {report_path}", exception)
        
        # Convert the dictionary's values back into a list for the final output.
        return list(findings_dict.values())