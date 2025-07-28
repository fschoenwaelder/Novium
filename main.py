import json
import sys

from dotenv import load_dotenv
import argparse
import os

from Tools import *

def get_base_prefix_compat():
    return (
            getattr(sys, "base_prefix", None)
            or getattr(sys, "real_prefix", None)
            or sys.prefix
    )


def in_virtualenv():
    return sys.prefix != get_base_prefix_compat()


def main():
    # main code here
    if not in_virtualenv():
        sys.exit("Script not started in a venv. Please active a venv to run this script")

if __name__ == '__main__':

    parser = argparse.ArgumentParser()

    parser.add_argument('-u', '--url', 
                        type=str, 
                        required=True, 
                        help="Target URL.")

    parser.add_argument("-sc", "--scrape",
                        default=False,
                        required=False,
                        action="store_true",
                        help="Scrape the target URL and use Gemini to retrieve possible weaknesses of the website")

    parser.add_argument("-c", "--context",
                        type=str,
                        required=False,
                        help="(Additional) Context of the website for Gemini")

    parser.add_argument("-as", "--automatic-scan",
                        default=False,
                        required=False,
                        action="store_true",
                        help="Start nuclei / zap with the newly created templates on the provided target")

    parser.add_argument('-v', '--verbose',
                        type=bool,
                        required=False,
                        default=False,
                        help="Verbose output.")

    args = parser.parse_args()

    target_url = args.url

    if target_url is None or len(target_url) < 1:
        raise Exception("No url given")

    load_dotenv()

    if args.verbose:
        os.environ["DEBUG"] = "true"

    if not args.scrape and not args.context:
        raise Exception("You must specify either --scrape or --context")

    webanalysis_result = None
    if args.scrape:
        webanalysis = WebAnalysis(target_url)
        webanalysis_result = webanalysis.run()

    gemini_connector = GeminiConnector()
    gemini_connector.set_system_prompt(tool="zap", use_predefined=True)
    gemini_connector.setup_gemini(use_schema=True)
    query = f"""
        **Objective:** Generate a factual cybersecurity reconnaissance report for the target URL, leveraging the provided "Web Scan Results" and any relevant "Tool Documentation".
        
        **Target URL:** {target_url}      
    """

    if args.context is not None and len(args.context) > 0:
        query += (
            "**Initial User Context / Specific Focus:**"
            f"{args.context}"
        )

    query += f"""
        **Web Scan Results (Detailed Reconnaissance Data):**
        {webanalysis_result}
        
        **Instructions for Analysis:**
        1.  Review the "Web Scan Results" thoroughly to identify technologies, configurations, and potential vulnerabilities.
        2.  If "Tool Documentation" is provided, use it as a primary source for factual information when discussing tool-specific aspects or validating findings related to known vulnerabilities (CVEs) or attack vectors.
        3.  Adhere strictly to the professional penetration tester persona and the rule: "Provide a factual reconnaissance report based *only* on the data provided. Do not make any assumptions."
        4.  Structure your final report clearly and professionally, combining insights from both the web scan results and any provided tool documentation.
    """
    zap_results = gemini_connector.run_query(query, tool_name="zap")
    zap_json_parsed = json.loads(zap_results)

    created_files = {'zap': [], 'nuclei': []}

    for tool_template in zap_json_parsed:
        file_path = ZapAdapter.save_template(tool_template["file_name"], tool_template["template"])
        created_files["zap"].append(file_path)

    gemini_connector.set_system_prompt(tool="nuclei", use_predefined=True)
    gemini_connector.setup_gemini(use_schema=True)

    nuclei_results = gemini_connector.run_query(query, tool_name="nuclei")
    nuclei_json_parsed = json.loads(nuclei_results)

    for tool_template in nuclei_json_parsed:
        file_path = NucleiAdapter.save_template(tool_template["file_name"], tool_template["template"])
        created_files["nuclei"].append(file_path)

    if args.automatic_scan:
        if len(created_files["nuclei"]) > 0:
            nuclei_adapter = NucleiAdapter(target_url, templates=created_files["nuclei"])
            nuclei_adapter.prepare_scan()
            report_file = nuclei_adapter.run_scan()
            findings = nuclei_adapter.parse_report(report_file)
            print(f"Nuclei: {findings}")

        if len(created_files["zap"]) > 0:
            zap_adapter = ZapAdapter(target_url)
            zap_adapter.prepare_scan(path=created_files["zap"][0])
            report_file = zap_adapter.run_scan()
            findings = zap_adapter.parse_report(report_file)
            print(f"Zap: {findings}")

    sys.exit(0)
