from abc import ABC, abstractmethod
import datetime
import os
from Misc.Logger import Logger
import time

class DastAdapter(ABC):

    def __init__(self, target_url: str, report_dir: str = "~/novium/dast_reports/", log_dir: str = "~/novium/logs", template_dir: str = "~/novium/templates/"):
        if not target_url.startswith(('http://', 'https://')):
            raise ValueError("Target URL muss mit http:// oder https:// beginnen.")

        if report_dir.startswith("~"):
            report_dir = os.path.expanduser(report_dir)

        if "$" in report_dir:
            report_dir = os.path.expandvars(report_dir)

        if log_dir.startswith("~"):
            log_dir = os.path.expanduser(log_dir)
        
        if "$" in log_dir:
            log_dir = os.path.expandvars(log_dir)

        if template_dir.startswith("~"):
            template_dir = os.path.expanduser(template_dir)

        if "$" in template_dir:
            template_dir = os.path.expandvars(template_dir)

        self.target_url = target_url
        self.report_dir = report_dir
        self.log_dir = log_dir
        self.template_dir = template_dir
        self.logger = Logger(f"{log_dir}/fallback.log")

        os.makedirs(self.report_dir, exist_ok=True)
        os.makedirs(self.log_dir, exist_ok=True)
        os.makedirs(self.template_dir, exist_ok=True)

    @abstractmethod
    def run_scan(self, **kwargs) -> str:
        pass

    @abstractmethod
    def prepare_scan(self, **kwargs):
        pass
    
    @abstractmethod
    def parse_report(self, report_path: str) -> list[dict]:
        pass

    @staticmethod
    def save_template(filename, template, template_dir="~/novium/templates"):
        if template_dir.startswith("~"):
            template_dir = os.path.expanduser(template_dir)

        if "$" in template_dir:
            template_dir = os.path.expandvars(template_dir)

        os.makedirs(template_dir, exist_ok=True)

        try:
            file_path = os.path.join(template_dir, str(int(time.time())) + "_" + filename)

            if not file_path.endswith(".yaml"):
                file_path += ".yaml"

            with open(file_path, 'w', encoding='utf-8') as f:
                f.writelines(template)

                print(f"writing to {file_path}")
                return file_path

        except Exception as e:
            print(f"An unexpected error occurred", e)
            pass

    def get_report_filename(self, tool_name: str, extension: str) -> str:
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        return os.path.join(self.report_dir, f"{tool_name}_report_{timestamp}.{extension}")
