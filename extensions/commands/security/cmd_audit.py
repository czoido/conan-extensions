import fnmatch
import os
import re
import requests
import yaml
import json
from rich.console import Console
from rich.table import Table
from conan.api.output import ConanOutput, Color
from conan.cli.printers.graph import print_graph_packages, print_graph_basic
from conan.cli.formatters.graph.graph_info_text import format_graph_info
from conan.cli.formatters.graph import format_graph_json
from conan.api.conan_api import ConanAPI
from conan.api.model import ListPattern
from conan.errors import ConanException
from conan.cli.command import conan_command, OnceArgument
from conan.cli.args import common_graph_args
from conans.model.recipe_ref import RecipeReference


def filter_graph(graph, package_filter=None):
    if package_filter is not None:
        graph["nodes"] = {id_: n for id_, n in graph["nodes"].items()
                          if any(fnmatch.fnmatch(n["ref"] or "", p) for p in package_filter)}
    return graph


def validate_args(args):
    if args.requires and (args.name or args.version or args.user or args.channel):
        raise ConanException("Can't use --name, --version, --user or --channel arguments with "
                             "--requires")
    if args.channel and not args.user:
        raise ConanException("Can't specify --channel without --user")
    if not args.path and not args.requires and not args.tool_requires:
        raise ConanException(
            "Please specify a path to a conanfile or a '--requires=<ref>'")
    if args.path and (args.requires or args.tool_requires):
        raise ConanException("--requires and --tool-requires arguments are incompatible with "
                             f"[path] '{args.path}' argument")


def default_formatter(results):
    display_vulnerabilities(results[0])
    display_patches(results[1])


def json_formatter(results):
    print(json.dumps(results[0], indent=4))


@conan_command(group="Security", formatters={"text": default_formatter, "json": json_formatter})
def audit(conan_api: ConanAPI, parser, *args):
    """
    Audit a single conan package from a remote server.

    It downloads just the recipe for the package, but not its transitive dependencies.
    """
    common_graph_args(parser)
    parser.add_argument("--check-updates", default=False, action="store_true",
                        help="Check if there are recipe updates")
    parser.add_argument("--package-filter", action="append",
                        help='Print information only for packages that match the patterns')
    parser.add_argument("--use-commit", action='store_true',
                        default=False, help='Use commit api request.')
    args = parser.parse_args(*args)

    # parameter validation
    validate_args(args)

    cwd = os.getcwd()
    path = conan_api.local.get_conanfile_path(
        args.path, cwd, py=None) if args.path else None

    # Basic collaborators, remotes, lockfile, profiles
    remotes = conan_api.remotes.list(args.remote) if not args.no_remote else []
    overrides = eval(
        args.lockfile_overrides) if args.lockfile_overrides else None
    lockfile = conan_api.lockfile.get_lockfile(lockfile=args.lockfile,
                                               conanfile_path=path,
                                               cwd=cwd,
                                               partial=args.lockfile_partial,
                                               overrides=overrides)
    profile_host, profile_build = conan_api.profiles.get_profiles_from_args(
        args)

    if path:
        deps_graph = conan_api.graph.load_graph_consumer(path, args.name, args.version,
                                                         args.user, args.channel,
                                                         profile_host, profile_build, lockfile,
                                                         remotes, args.update,
                                                         check_updates=args.check_updates,
                                                         is_build_require=False)
    else:
        deps_graph = conan_api.graph.load_graph_requires(args.requires, args.tool_requires,
                                                         profile_host, profile_build, lockfile,
                                                         remotes, args.update,
                                                         check_updates=args.check_updates)
    print_graph_basic(deps_graph)
    if deps_graph.error:
        ConanOutput().info("Graph error", Color.BRIGHT_RED)
        ConanOutput().info("    {}".format(deps_graph.error), Color.BRIGHT_RED)
    else:
        conan_api.graph.analyze_binaries(deps_graph, args.build, remotes=remotes, update=args.update,
                                         lockfile=lockfile)
        print_graph_packages(deps_graph)

        conan_api.install.install_system_requires(deps_graph, only_info=True)
        conan_api.install.install_sources(deps_graph, remotes=remotes)

        lockfile = conan_api.lockfile.update_lockfile(lockfile, deps_graph, args.lockfile_packages,
                                                      clean=args.lockfile_clean)
        conan_api.lockfile.save_lockfile(lockfile, args.lockfile_out, cwd)

    serial = deps_graph.serialize()
    serial = filter_graph(serial, args.package_filter)

    refs_to_audit = [RecipeReference.loads(
        n["ref"]) for n in serial["nodes"].values() if n["id"] != "0"]

    all_vulnerabilities = []
    all_patches = []

    for ref in refs_to_audit:
        osv_payload = get_osv_payload(conan_api, ref, args.use_commit)
        if osv_payload:
            print("request:", osv_payload)
            osv_response = requests.post("https://api.osv.dev/v1/query", json=osv_payload)
            patches_info = get_patches_info(conan_api, ref)

            all_vulnerabilities.append(osv_response.json())
            all_patches.append(patches_info)

    return (all_vulnerabilities, all_patches)


def get_osv_payload(conan_api, ref_to_audit, use_commit):
    conandata_path = os.path.join(
        conan_api.cache.export_path(ref_to_audit), "conandata.yml")
    if "cci" in str(ref_to_audit.version) or use_commit:
        with open(conandata_path, 'r') as file:
            parsed_yaml = yaml.safe_load(file)

        try:
            url = parsed_yaml['sources'][str(ref_to_audit.version)][0]['url']
        except KeyError:
            url = parsed_yaml['sources'][str(ref_to_audit.version)]['url']

        tag = extract_tag(url) or str(ref_to_audit.version)
        if not tag:
            raise Exception("No tags found")
        commit_hash = get_commit_hash(url, tag)
        if commit_hash:
            return {"commit": commit_hash}
    else:
        return {"package": {"name": str(ref_to_audit.name)}, "version": str(ref_to_audit.version)}


def get_patches_info(conan_api, ref_to_audit):
    conandata_path = os.path.join(
        conan_api.cache.export_path(ref_to_audit), "conandata.yml")
    with open(conandata_path, 'r') as file:
        parsed_yaml = yaml.safe_load(file)
    return parsed_yaml.get('patches', {}).get(str(ref_to_audit.version), [])


def extract_tag(url):
    match = re.search(
        r'/download/(v?\d+\.\d+\.\d+)/|/archive/(v?\d+\.\d+\.\d+)\.tar\.gz|/tags/(.+)\.tar\.gz', url)
    return match.group(1) or match.group(2) or match.group(3) if match else None


def get_commit_hash(url, tag):
    org_project = "/".join(url.split('/')[3:5])
    headers = {"Authorization": f"token {os.environ.get('GH_TOKEN')}"}
    response = requests.get(f"https://api.github.com/repos/{org_project}/git/ref/tags/{tag}", headers=headers).json()
    commit_url = response.get('object', {}).get('url')
    if commit_url:
        return requests.get(commit_url, headers=headers).json().get('object', {}).get('sha', requests.get(commit_url, headers=headers).json()['sha'])


def display_vulnerabilities(all_vulnerabilities_data):
    console = Console()
    table = Table(title="Vulnerabilities", show_header=True, header_style="bold green")
    table.add_column("ID", style="dim", width=12)
    table.add_column("Details")
    table.add_column("Published")
    table.add_column("Modified")
    table.add_column("References", justify="right")

    for data_json in all_vulnerabilities_data:
        for vuln in data_json.get("vulns", []):
            references = "\n".join([ref["url"] for ref in vuln["references"]])
            table.add_row(vuln["id"], vuln["details"], vuln["published"], vuln["modified"], references)

    console.print(table) if all_vulnerabilities_data else print("No vulnerabilities found.")


def display_patches(all_patches_data):
    console = Console()
    table = Table(title="Patches", show_header=True, header_style="bold green")
    table.add_column("Description")
    table.add_column("File")
    table.add_column("Type")

    for patches in all_patches_data:
        for patch in patches:
            table.add_row(patch["patch_description"], patch["patch_file"], patch["patch_type"])

    console.print(table) if all_patches_data else print("No patches found for this version.")
