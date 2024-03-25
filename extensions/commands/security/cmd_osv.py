import os
import re
import requests
import yaml
import json
from rich.console import Console
from rich.table import Table
from conan.api.conan_api import ConanAPI
from conan.errors import ConanException
from conan.api.model import ListPattern
from conan.cli.command import conan_command, OnceArgument


def display_vulnerabilities(data_json):
    console = Console()
    table = Table(title="Vulnerabilities", show_header=True, header_style="bold green")
    table.add_column("ID", style="dim", width=15)
    table.add_column("Details")
    # table.add_column("Published")
    # table.add_column("Modified")
    # table.add_column("References", justify="right")

    vulns = data_json.get("vulns", [])

    for vuln in vulns:
        # references = "\n".join([ref["url"] for ref in vuln["references"]])
        table.add_row(
            vuln["id"],
            vuln["details"],  # , vuln["published"], vuln["modified"]#, references
        )

    console.print(table) if data_json else console.print("No vulnerabilities found.")
    console.print(f"Total vulnerabilities found: {len(vulns)}", style="bold yellow")


def display_patches(patches):
    console = Console()
    table = Table(title="Patches", show_header=True, header_style="bold green")
    table.add_column("Description")
    table.add_column("File")
    table.add_column("Type")

    for patch in patches:
        table.add_row(
            patch["patch_description"], patch["patch_file"], patch["patch_type"]
        )

    console.print(table) if patches else print("No patches found for this version.")


def default_formatter(results):
    display_vulnerabilities(results[0])
    display_patches(results[1])


def json_formatter(results):
    print(json.dumps(results[0], indent=4))


def get_patches_info(conan_api, ref_to_audit):
    conandata_path = os.path.join(
        conan_api.cache.export_path(ref_to_audit), "conandata.yml"
    )
    with open(conandata_path, "r") as file:
        parsed_yaml = yaml.safe_load(file)
    return parsed_yaml.get("patches", {}).get(str(ref_to_audit.version), [])


def extract_tag(url):
    match = re.search(
        r"/download/(v?\d+\.\d+\.\d+)/|/archive/(v?\d+\.\d+\.\d+)\.tar\.gz|/tags/(.+)\.tar\.gz",
        url,
    )
    return match.group(1) or match.group(2) or match.group(3) if match else None


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
        raise ConanException(
            f"There was an error trying to get commit hash from the '{tag}' tag."
            "Please, try to provide the commit hash in the --use-commit argument"
        )


def get_osv_payload(conan_api, ref_to_audit, use_commit):
    conandata_path = os.path.join(
        conan_api.cache.export_path(ref_to_audit), "conandata.yml"
    )
    if "cci" in str(ref_to_audit.version) or use_commit == "autodetect":
        with open(conandata_path, "r") as file:
            parsed_yaml = yaml.safe_load(file)

        try:
            url = parsed_yaml["sources"][str(ref_to_audit.version)][0]["url"]
        except KeyError:
            url = parsed_yaml["sources"][str(ref_to_audit.version)]["url"]

        tag = extract_tag(url) or str(ref_to_audit.version)
        if not tag:
            raise Exception("No tags found")
        commit_hash = get_commit_hash(url, tag)
        return {"commit": commit_hash}
    elif use_commit:
        return {"commit": use_commit}
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
    Audit a single conan package from a remote server.

    It downloads just the recipe for the package, but not its transitive dependencies.
    """
    parser.add_argument(
        "reference",
        nargs="?",
        help="Conan package reference in the form 'pkg/version#revision', If revision is not specified, it is assumed latest one.",
    )
    parser.add_argument(
        "--use-commit",
        nargs="?",
        const="autodetect",
        default=None,
        help="Use commit api request. Takes an optional commit hash value. If no value is provided, it will autodetect.",
    )
    parser.add_argument(
        "-r",
        "--remote",
        action=OnceArgument,
        required=True,
        help="Download from this specific remote",
    )

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

    osv_payload = get_osv_payload(conan_api, ref_to_audit, args.use_commit)
    osv_response = requests.post("https://api.osv.dev/v1/query", json=osv_payload)

    patches_info = get_patches_info(conan_api, ref_to_audit)

    return (osv_response.json(), patches_info)
