import os
import subprocess

import time
import json

from Tools.DastAdapter import DastAdapter

class ZapAdapter(DastAdapter):

    system_prompt = ("You are an expert cybersecurity automation engineer specializing in OWASP ZAP's Automation Framework. Your primary goal is to generate a **single, fully functional, standalone YAML scan plan** based on the user's request, one for each distinct security vulnerability or flaw identified in the input."
                    "\n"
                    "**Crucial Constraints for Plan Generation:**"
                    "\n"
                    "1.  **Self-Contained & Executable:** The generated plan must be immediately runnable without any external dependencies. Absolutely no placeholders (e.g., `[...]`, `YOUR_VALUE`), incomplete sections (e.g., `TODO`, `# Add logic here`), or references to external files."
                    "2.  **Realistic Values:** Invent and use concrete, realistic values for all necessary fields to ensure immediate and practical executability."
                    "3.  **Environment & Target:** Every plan MUST include an `env` (environment) section that defines necessary parameters, including a `context` and a `target` URL (e.g., `https://example.com`)."
                    "4.  **Logical Scan Order:** Any job that consumes URL data (e.g., `activeScan`, `passiveScan-wait`) MUST be preceded by a discovery job (e.g., `spider`, `ajaxSpider`) that populates the site tree."
                    "5.  **Mandatory Reporting:** Every plan MUST conclude with a `report` job to generate and save the scan results in a specified format and location."
                    "6.  **Logical Filenames:** Create a logical, lowercase, snake_case filename for the plan, clearly indicating its purpose. Include the `.yaml` extension (e.g., `full_scan_plan.yaml`, `api_scan_with_auth.yaml`)."
                    "\n"
                    "**Guidance for Ensuring Plan Quality:**"
                    "\n"
                    "* **Syntactical Correctness and Executability:** Before outputting, you **MUST** internally re-validate that the generated YAML plan is syntactically correct and adheres to all ZAP Automation Framework schema requirements."
                    "* **Job-Specific Parameters:** Leverage your knowledge of ZAP's jobs (`spider`, `activeScan`, etc.) to include relevant and effective parameters. For example, configure the `activeScan` with appropriate policies."
                    "* **Efficiency and Focus:** Design the scan plan to be focused and efficient. Only include jobs necessary to achieve the requested scan objective. Avoid including redundant or unnecessary jobs."
                    "* **Comprehensive Reporting**: Every scan plan MUST conclude with a report job to save the findings. Configure this job to generate a JSON report by setting its template parameter to a JSON-based option (e.g., traditional-json) and define a clear reportFile name."
                    "\n"
                    "**Output Format - CRITICAL (Follow this exactly):**"
                    "Return **ONLY** a single JSON object. This JSON object must map the generated filename (as a string, including the `.yaml` extension) to its corresponding complete YAML plan (as a single string, including all newlines and proper YAML indentation)."
                )

    def __init__(self, target_url: str, 
                 report_dir: str = "~/novium/dast_reports/zap",
                 log_dir: str = "~/novium/logs/zap",
                 template_dir: str = "~/novium/templates/zap",
                 working_dir: str = "~/novium/working/zap",
                 zap_executable_path: str = "/Applications/ZAP.app/Contents/Java/zap.sh"):

        super().__init__(target_url=target_url, report_dir=report_dir, log_dir=log_dir, template_dir=template_dir)

        # Check if os path exists
        if not os.path.isfile(zap_executable_path):
            raise FileNotFoundError(f"ZAP executable not found at: {zap_executable_path}")

        if working_dir.startswith("~"):
            working_dir = os.path.expanduser(working_dir)

        if "$" in report_dir:
            working_dir = os.path.expandvars(working_dir)

        self.working_dir = working_dir
        self.zap_executable_path = zap_executable_path

    def prepare_scan(self, **kwargs):
        # Get path from kwargs
        automation_yaml_path = kwargs.get("path", None)

        # Check if path is set
        if automation_yaml_path is None:
            raise Exception("No path given.")

        self.logger.info(f"Start ZAP Automation Framework with plan: {automation_yaml_path}")

        # Check if script exists
        if not os.path.isfile(automation_yaml_path):
            raise Exception(f"Automation plan not found at {automation_yaml_path}")

        cmd_params = kwargs.get("params", [])
        workdir = os.path.join(self.working_dir, str(int(time.time())))

        os.makedirs(workdir, exist_ok=True)

        self.command = [
            self.zap_executable_path,
            '-cmd',
            '-dir', workdir,
            '-autorun', 
            *cmd_params,
            automation_yaml_path
        ]
        
        self.logger.info(f"Execute command: {' '.join(self.command)}")

    def run_scan(self, **kwargs) -> str:
        try:
            result = subprocess.run(
                self.command,
                capture_output=True, 
                text=True,
                check=False,
            )

            if os.environ.get("LOGGING_ENABLED") == 1 or os.environ.get("DEBUG") == 1:
                if result.stdout:
                    self.logger.info(f"ZAP STDOUT: {result.stdout}")

                if result.stderr:
                    self.logger.info(f"ZAP STDERR: {result.stderr}")

            if result.returncode != 0:
                self.logger.info(f"ZAP scan failed with exit code: {result.returncode}.")
            
            self.logger.info("ZAP Automation Framework scan successfully executed.")

        except FileNotFoundError:
            self.logger.error(f"Executable not found at '{self.zap_executable_path}'. Please validate the path.")

        except Exception as exception:
            self.logger.error(f"An unexpected error occurred:", exception)

        return ""

    @staticmethod
    def save_template(filename, template, template_dir="~/novium/templates/zap"):
        return DastAdapter.save_template(filename=filename, template=template, template_dir=template_dir)

    def parse_report(self, report_path: str) -> list[dict]:
        self.logger.info(f"Parse Report from {report_path}...")
        parsed_findings = []

        try:
            with open(report_path, 'r', encoding='utf-8') as f:
                report_data = json.load(f)

            if 'site' in report_data:
                for site in report_data['site']:
                    if 'alerts' in site:
                        for alert in site['alerts']:
                            finding = {
                                'name': alert.get('alertName'),
                                'description': alert.get('description'),
                                'severity': alert.get('riskDesc'),
                                'confidence': alert.get('confidence'),
                                'url': alert.get('uri'),
                                'solution': alert.get('solution'),
                                'references': alert.get('references'),
                                'instances': alert.get('instances', [])
                            }

                            self.logger.info(f"Identified vulnerability {finding}")

                            parsed_findings.append(finding)
            else:
                self.logger.warning(
                    f"No 'site' key found in ZAP report: {report_path}. Report structure might be unexpected.")

        except Exception as e:
            self.logger.error(f"An unexpected error occurred while parsing ZAP report: {e}")

        self.logger.info(f"Finished parsing ZAP report. Found {len(parsed_findings)} findings.")
        return parsed_findings