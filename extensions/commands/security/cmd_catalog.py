import json
import os
import textwrap
import time
import requests
from rich.console import Console
from rich.table import Table
from rich.progress import Progress

from conan.cli.command import conan_command
from conan.errors import ConanException


def display_vulnerabilities(list_of_data_json):
    console = Console()
    severity_to_color = {
        "Critical": "bold red",
        "High": "bold yellow",
        "Medium": "yellow",
        "Low": "green",
        "Informational": "blue",
        "Unknown": "grey",
    }

    # Create a table for the vulnerabilities
    table = Table(title="Vulnerabilities", show_header=False, header_style="bold green")
    table.add_column("ID", style="dim", width=15)
    table.add_column("Details")
    table.add_column("Severity")

    total_vulnerabilities = 0

    for data_json in list_of_data_json:
        if (
            not data_json
            or "data" not in data_json
            or "packageVersion" not in data_json["data"]
        ):
            # If there's an issue with the current JSON, skip to the next one
            continue

        package_version = data_json["data"]["packageVersion"]
        #console.print(f"Package: {package_version['package']['name']} Version: {package_version['version']}", style="bold green")

        vulnerabilities = package_version["vulnerabilities"]["edges"]
        total_vulnerabilities += len(vulnerabilities)
        if vulnerabilities:
            table.add_section()
            table.add_row(
                None,
                f"[red]{package_version['package']['name']}/{package_version['version']}: {total_vulnerabilities} vulnerabilities found[/]",
                None,
            )
            table.add_section()
            sorted_vulns = sorted(vulnerabilities, key=lambda x: x["node"]["name"])
            for vuln in sorted_vulns:
                node = vuln["node"]
                severity_color = severity_to_color.get(node["severity"], "grey")
                # Add rows to the table with the corresponding severity color
                table.add_row(
                    node["name"],
                    textwrap.shorten(node["description"], width=80, placeholder="..."),
                    f"[{severity_color}]{node['severity']}[/]",
                )
        else:
                table.add_section()
                table.add_row(
                    None,
                    f"[green]{package_version['package']['name']}/{package_version['version']}: no vulnerabilities found[/]",
                    None,
                )
                table.add_section()


    console.print(table)
    console.print(
        f"Total vulnerabilities found: {total_vulnerabilities}", style="bold yellow"
    )



def json_formatter(results):
    for package_vulns in results:
        print(json.dumps(package_vulns, indent=4))


query = textwrap.dedent("""
            query packageVersionDetails($type: String!, $name: String!, $version: String!) {
                packageVersion(name: $name, type: $type, version: $version) {
                    version
                    published
                    vcsUrl
                    homepage
                    licenseInfo {
                        expression
                        licenses {
                            name
                            isSpdx
                        }
                    }
                    vulnerabilities(first: 100) {
                        edges {
                            node {
                                name
                                description
                                severity
                                cvss {
                                    preferredBaseScore
                                }
                                aliases
                                advisories {
                                    name
                                }
                            }
                        }
                    }
                    package {
                        name
                        versions(first:50) {
                            totalCount
                        }
                    }
                }
            }
            """)

@conan_command(
    group="Security",
    formatters={"text": display_vulnerabilities, "json": json_formatter},
)
def catalog(conan_api, parser, *args):
    """
    Check details for a specific package version.
    """
    parser.add_argument(
        "path",
        help="Path to a folder containing a recipe (conanfile.py or conanfile.txt) or to a recipe file. e.g., ./my_project/conanfile.txt.",
    )

    parser.add_argument(
        "--catalog-url",
        default=os.getenv("CATALOG_URL"),
        help="GraphQL endpoint URL.",
    )

    parser.add_argument(
        "--username",
        default=os.getenv("CATALOG_USER"),
        help="Username for authentication. Optional.",
    )

    parser.add_argument(
        "--password",
        default=os.getenv("CATALOG_PASSWORD"),
        help="Password for authentication. Optional.",
    )

    args = parser.parse_args(*args)

    graph_result = conan_api.command.run(["graph", "info", args.path])
    dependencies = graph_result.get("graph").nodes[1:]

    transitive_vulnerabilities = []
    with Progress() as progress:
        task = progress.add_task("[cyan]Requesting package info...", total=len(dependencies))
        for dep in dependencies:
            name = str(dep.ref.name)
            version = str(dep.ref.version)

            headers = {"Content-Type": "application/json", "Accept": "application/json"}


            if args.catalog_url is None:
                raise ConanException("Please specify the catalog url via the '--catalog-url' argument or the CATALOG_URL environment variable")

            if args.username and args.password:
                catalog_auth = (args.username, args.password)
            else:
                catalog_auth = None

            response = requests.post(
                args.catalog_url,
                auth=catalog_auth,
                headers=headers,
                json={
                    "query": query,
                    "variables": {"name": name, "type": "conan", "version": version},
                    "operationName": "packageVersionDetails",
                },
            )
            data_json = response.json()
            transitive_vulnerabilities.append(data_json)
            progress.update(task, description=f"[cyan]Processing {name}/{version}...",advance=1)
            time.sleep(0.05)
    return transitive_vulnerabilities
