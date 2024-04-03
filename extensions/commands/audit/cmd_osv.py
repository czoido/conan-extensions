import os
import re
import textwrap
import time
import requests
import yaml
import json
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
from conan.api.conan_api import ConanAPI
from conan.errors import ConanException
from conan.cli.command import conan_command


def display_vulnerabilities(list_of_data_json):
    console = Console()
    table = Table(title="Vulnerabilities", show_header=False)
    table.add_column("ID", style="dim", width=15)
    table.add_column("Details")

    num_vulns = 0
    packages_without_vulns = []  # List to keep track of packages without vulnerabilities

    for data_json in list_of_data_json:
        vulns = data_json.get("vulns", [])
        ref = data_json.get('ref')  # Reference to the package

        if vulns:
            table.add_section()
            table.add_row(
                None,
                f"[red]{ref}: {len(vulns)} vulnerabilities[/]\n",
            )
            for vuln in vulns:
                table.add_row(
                    vuln["id"],
                    textwrap.shorten(vuln["details"], width=80, placeholder="...")
                )
                num_vulns += 1
        else:
            packages_without_vulns.append(f"[green]{ref}[/]")  # Add package ref to the list

    # Print the table only if there are vulnerabilities found
    if num_vulns > 0:
        console.print(table)

    # Print the total number of vulnerabilities found
    style = "bold yellow" if num_vulns>0 else "bold green"
    console.print(f"Total vulnerabilities found: {num_vulns}", style=style)

    # Print the summary for packages without vulnerabilities
    if packages_without_vulns:
        console.print(
            "No vulnerabilities found in: " + ", ".join(packages_without_vulns),
            style="bold green"
        )



def default_formatter(results):
    display_vulnerabilities(results)


def json_formatter(results):
    print(json.dumps(results, indent=4))


def get_vulnerabilities(conan_api, dep):
    if "cci" not in str(dep.ref.version):
        osv_payload = get_osv_payload(conan_api, dep.ref)
        osv_response = requests.post("https://api.osv.dev/v1/query", json=osv_payload)
        if osv_response.json():
            return osv_response.json()

    osv_payload = get_osv_payload(conan_api, dep.ref, by_commit=True)
    if (osv_payload):
        osv_response = requests.post("https://api.osv.dev/v1/query", json=osv_payload)
        if osv_response.json():
            return osv_response.json()
    return {}


def get_commit_hash(url, tag):
    try:
        org_project = "/".join(url.split("/")[3:5])
        headers = {"Authorization": f"token {os.environ.get('GH_TOKEN')}"}
        response = requests.get(
            f"https://api.github.com/repos/{org_project}/git/ref/tags/{tag}",
            headers=headers,
        )
        commit_url = response.json()["object"]["url"]
        return (
            requests.get(commit_url, headers=headers)
            .json()
            .get("object", {})
            .get("sha", requests.get(commit_url, headers=headers).json().get("sha"))
        )
    except Exception as e:
        pass


def extract_tag(urls):
    if not isinstance(urls, list):
        urls = [urls]
    
    github_urls = [_url for _url in urls if "github" in _url]
    
    if github_urls:
        match = re.search(
            r"/download/(v?\d+\.\d+\.\d+)/|/archive/(v?\d+\.\d+\.\d+)\.tar\.gz|/tags/(.+)\.tar\.gz",
            github_urls[0],
        )
        return match.group(1) or match.group(2) or match.group(3) if match else None

def get_osv_payload(conan_api, ref_to_audit, by_commit=False):
    if by_commit:
        conandata_path = os.path.join(
            conan_api.cache.export_path(ref_to_audit), "conandata.yml"
        )
        with open(conandata_path, "r") as file:
            parsed_yaml = yaml.safe_load(file)

        try:
            url = parsed_yaml["sources"][str(ref_to_audit.version)][0].get("url")
        except KeyError:
            url = parsed_yaml["sources"][str(ref_to_audit.version)].get("url")

        if url:
            tag = extract_tag(url)
            if tag:
                commit_hash = get_commit_hash(url, tag)
                if commit_hash:
                    return {"commit": commit_hash}
        return {}
    else:
        return {
            "package": {"name": str(ref_to_audit.name)},
            "version": str(ref_to_audit.version),
        }


@conan_command(
    group="Security", formatters={"text": default_formatter, "json": json_formatter}
)
def osv(conan_api: ConanAPI, parser, *args):
    """
    Use OSV to check security details for a Conan graph using a conanfile.txt/py.
    """
    parser.add_argument(
        "path",
        help="Path to a folder containing a recipe (conanfile.py or conanfile.txt) or to a recipe file. e.g., ./my_project/conanfile.txt.",
    )

    args = parser.parse_args(*args)


    if os.getenv("GH_TOKEN") is None:
        raise ConanException("Please specify a GitHub token with the GH_TOKEN environment variable")

    graph_result = conan_api.command.run(["graph", "info", args.path])
    root = graph_result.get("graph").nodes[0]
    
    transitive_vulnerabilities = []
    with Progress() as progress:
        task = progress.add_task("[cyan]Requesting package info...", total=len(root.transitive_deps))
        for dep in root.transitive_deps:
            data_json = get_vulnerabilities(conan_api, dep)
            data_json.update({"ref": str(dep.ref)})
            transitive_vulnerabilities.append(data_json)
            progress.update(task, description=f"[cyan]Processing {str(dep.ref)}...",advance=1)
            time.sleep(0.1)
    return transitive_vulnerabilities
