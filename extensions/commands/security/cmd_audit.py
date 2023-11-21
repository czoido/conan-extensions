import os
import re
import requests
import yaml
import json

from rich.console import Console
from rich.table import Table
from conan.api.conan_api import ConanAPI
from conan.api.model import ListPattern
from conan.cli.command import conan_command, OnceArgument


@conan_command(group="Security", formatters={})
def audit(conan_api: ConanAPI, parser, *args):
    """
    Audit a single conan package from a remote server.

    It downloads just the recipe for the package, but not its transitive dependencies.
    """

    parser.add_argument('reference', nargs="?",
                        help="Conan package reference in the form 'pkg/version#revision', "
                             "If revision is not specified, it is assumed latest one.")
    parser.add_argument("--use-commit", action='store_true', default=False,
                        help='Use commit api request.')

    parser.add_argument("-r", "--remote", action=OnceArgument, required=True,
                        help='Download from this specific remote')

    args = parser.parse_args(*args)

    remote = conan_api.remotes.get(args.remote)

    ref_pattern = ListPattern(args.reference, only_recipe=True)
    package_list = conan_api.list.select(ref_pattern, remote=remote)

    refs = []
    prefs = []
    for ref, recipe_bundle in package_list.refs().items():
        refs.append(ref)
        for pref, _ in package_list.prefs(ref, recipe_bundle).items():
            prefs.append(pref)

    ref_to_audit = refs[0]

    conan_api.download.recipe(ref_to_audit, remote)

    osv_api_url = "https://api.osv.dev/v1/query"

    if "cci" in str(ref_to_audit.version) or args.use_commit:

        conandata_path = os.path.join(conan_api.cache.export_path(ref_to_audit), "conandata.yml")

        with open(conandata_path, 'r') as file:
            parsed_yaml = yaml.safe_load(file)

        try:
            url = parsed_yaml['sources'][str(ref_to_audit.version)][0]['url']
        except KeyError:
            url = parsed_yaml['sources'][str(ref_to_audit.version)]['url']

        tag = None

        match = re.search(r'/download/(v?\d+\.\d+\.\d+)/|/archive/(v?\d+\.\d+\.\d+)\.tar\.gz', url)
        if match:
            tag = match.group(1) if match.group(1) else (match.group(2) if match.group(2) else None)

        #print(url, tag)
        if not tag:
            match = re.search(r'/tags/(.+)\.tar\.gz', url)
            if match:
                tag = match.group(1) if match else None

        if not tag:
            tag = str(ref_to_audit.version)

        if not tag:
            raise Exception("No tags found")

        repo_url_parts = url.split('/')
        org_project = "/".join(repo_url_parts[3:5])

        gh_token = os.environ.get("GH_TOKEN")
        headers = {"Authorization": f"token {gh_token}"}

        ls_remote_url = f"https://api.github.com/repos/{org_project}/git/ref/tags/{tag}"

        #print(ls_remote_url)
        response = requests.get(ls_remote_url, headers=headers)
        #print(ls_remote_url, response)
        commit_url = response.json()['object']['url']
        #print(commit_url)

        commit_response = requests.get(commit_url, headers=headers)
        #print(commit_url, commit_response)

        try:
            commit_hash = commit_response.json()['object']['sha']
        except KeyError:
            commit_hash = commit_response.json()['sha']

        osv_payload = {"commit": commit_hash}

    else:
        osv_payload = {"package": {"name": str(ref_to_audit.name)}, "version": str(ref_to_audit.version)}


    osv_response = requests.post(osv_api_url, json=osv_payload)

    response_json = osv_response.json()

    if response_json:
        pretty_json = json.dumps(response_json, indent=4)
        data_json = json.loads(pretty_json)  # Reemplaza your_json_string con tu JSON

        console = Console()
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("ID", style="dim", width=12)
        table.add_column("Details")
        table.add_column("Published")
        table.add_column("Modified")
        table.add_column("References", justify="right")

        for vuln in data_json["vulns"]:
            references = "\n".join([ref["url"] for ref in vuln["references"]])
            table.add_row(
                vuln["id"],
                vuln["details"],
                vuln["published"],
                vuln["modified"],
                references
            )

        console.print(table)
    else:
        print("No vulnerabilities found.")