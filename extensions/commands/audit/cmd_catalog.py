import json
import os
import textwrap
import requests
from conan.api.output import cli_out_write
from conan.cli.args import common_graph_args, validate_common_graph_args
from conan.cli.printers.graph import print_graph_packages, print_graph_basic
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
from rich.text import Text
from rich.panel import Panel

from conan.cli.command import conan_command


def display_vulnerabilities(list_of_data_json):
    console = Console()
    console.print("\n")
    table = Table(title="Vulnerabilities", show_header=False, header_style="bold green")
    table.add_column("ID", style="dim", width=15)
    table.add_column("Details")

    total_vulnerabilities = 0
    packages_without_vulns = []
    if not list_of_data_json \
            or "errors" in list_of_data_json \
            or "data" not in list_of_data_json \
            or list_of_data_json["data"] is None:
        console.print("No vulnerabilities found")
        return

    for library_key, library_data in list_of_data_json["data"].items():
        vulnerabilities = library_data["vulnerabilities"]["edges"]
        ref = f"{library_data['package']['name']}/{library_data['version']}"
        if vulnerabilities:
            # Accumulate total vulnerabilities and add them to the table
            table.add_section()
            table.add_row(
                None,
                f"[red]{ref}: {len(vulnerabilities)} vulnerabilities[/]\n",
            )
            total_vulnerabilities += len(vulnerabilities)
            sorted_vulns = sorted(vulnerabilities, key=lambda x: x["node"]["name"])
            for vuln in sorted_vulns:
                node = vuln["node"]
                reference_url = node["references"][0] if node["references"] else "#"
                vulnerability_name = Text(node["name"], style="link " + reference_url)
                table.add_row(
                    vulnerability_name,
                    textwrap.shorten(node["description"], width=80, placeholder="...")
                )
        else:
            # Add package name to the list of packages without vulnerabilities
            packages_without_vulns.append(f"[white]{ref}[/]")

    # Print the table only if there are vulnerabilities found
    if total_vulnerabilities > 0:
        console.print(table)

    style = "bold yellow" if total_vulnerabilities > 0 else "bold green"
    console.print(
        f"Total vulnerabilities found: {total_vulnerabilities}", style=style
    )

    # Print the list of packages without vulnerabilities
    if packages_without_vulns:
        console.print(
            "No vulnerabilities found in: " + ", ".join(packages_without_vulns)
        )
    console.print("\n")
    console.print(
        "Vulnerability information provided by [link=https://jfrog.com/help/r/jfrog-catalog/jfrog-catalog]JFrog Catalog[/]",
        style="bold green")
    console.print("\n")


def json_formatter(results):
    cli_out_write(json.dumps(results, indent=4))


def get_vulnerabilities(conan_api, refs, token, console):
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    result = {"data": {}}
    with Progress(console=console) as progress:
        task = progress.add_task("[cyan]Requesting information...", total=len(refs))
        for ref in refs:
            progress.update(task, description=f"[cyan]Requesting security information for {ref}...", advance=0)
            response = requests.post(
                "http://127.0.0.1:5000/api/v1/query",
                headers=headers,
                json={
                    "reference": ref,
                },
            )
            progress.update(task, description=f"[cyan]Requested security information for {ref}...", advance=1)
            result["data"].update(response.json()["data"])
    return result


@conan_command(
    group="Security",
    formatters={"text": display_vulnerabilities, "json": json_formatter},
)
def catalog(conan_api, parser, *args):
    """
    Use JFrog Catalog to check security details for a Conan graph using a conanfile.txt/py.
    """
    common_graph_args(parser)
    parser.add_argument("--check-updates", default=False, action="store_true",
                        help="Check if there are recipe updates")
    parser.add_argument("--build-require", action='store_true', default=False,
                        help='Whether the provided reference is a build-require')

    parser.add_argument("-t", "--token", help="Conan Catalog API token")
    args = parser.parse_args(*args)

    # parameter validation
    validate_common_graph_args(args)

    cwd = os.getcwd()
    path = conan_api.local.get_conanfile_path(args.path, cwd, py=None) if args.path else None

    # Basic collaborators, remotes, lockfile, profiles
    remotes = conan_api.remotes.list(args.remote) if not args.no_remote else []
    overrides = eval(args.lockfile_overrides) if args.lockfile_overrides else None
    lockfile = conan_api.lockfile.get_lockfile(lockfile=args.lockfile,
                                               conanfile_path=path,
                                               cwd=cwd,
                                               partial=args.lockfile_partial,
                                               overrides=overrides)
    profile_host, profile_build = conan_api.profiles.get_profiles_from_args(args)

    # TODO: Make this load only either a name of a pkglist, don't let it build the graph
    # Like this for now so we can test for larger graphs directly

    if path:
        deps_graph = conan_api.graph.load_graph_consumer(path, args.name, args.version,
                                                         args.user, args.channel,
                                                         profile_host, profile_build, lockfile,
                                                         remotes, args.update,
                                                         check_updates=args.check_updates,
                                                         is_build_require=args.build_require)
    else:
        deps_graph = conan_api.graph.load_graph_requires(args.requires, args.tool_requires,
                                                         profile_host, profile_build, lockfile,
                                                         remotes, args.update,
                                                         check_updates=args.check_updates)
    print_graph_basic(deps_graph)
    if not deps_graph.error:
        conan_api.graph.analyze_binaries(deps_graph, args.build, remotes=remotes, update=args.update,
                                         lockfile=lockfile)
        print_graph_packages(deps_graph)

        conan_api.install.install_system_requires(deps_graph, only_info=True)
        conan_api.install.install_sources(deps_graph, remotes=remotes)

        lockfile = conan_api.lockfile.update_lockfile(lockfile, deps_graph, args.lockfile_packages,
                                                      clean=args.lockfile_clean)
        conan_api.lockfile.save_lockfile(lockfile, args.lockfile_out, cwd)
    else:
        return {"error": deps_graph.error}

    refs = list(set(f"{node.ref.name}/{node.ref.version}" for node in deps_graph.nodes[1:]))

    console = Console()

    panel = Panel("Calculating Conan graph", style="bold green", expand=False)
    console.print(panel)

    console.print(f"Found {len(refs)} packages in the Conan graph: {refs}")

    panel = Panel("Requesting vulnerability information to JFrog Catalog", style="bold green", expand=False)

    console.print("\n")
    console.print(panel)
    console.print("\n")

    return get_vulnerabilities(conan_api, refs, args.token, console)
