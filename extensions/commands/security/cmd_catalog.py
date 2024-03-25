import json
import textwrap
import requests
from rich.console import Console
from rich.table import Table
from conan.cli.command import conan_command


def display_vulnerabilities(data_json):
    console = Console()
    if (
        not data_json
        or "data" not in data_json
        or "packageVersion" not in data_json["data"]
    ):
        console.print("No package version details found.", style="bold red")
        return

    package_version = data_json["data"]["packageVersion"]
    console.print(f"Version: {package_version['version']}", style="bold green")
    console.print(f"Published: {package_version['published']}", style="bold green")
    console.print(f"VCS URL: {package_version['vcsUrl']}", style="bold green")
    console.print(f"Homepage: {package_version['homepage']}", style="bold green")
    console.print(
        f"License: {package_version['licenseInfo']['expression']}", style="bold green"
    )

    severity_to_color = {
        "Critical": "bold red",
        "High": "bold yellow",
        "Medium": "yellow",
        "Low": "green",
        "Informational": "blue",
        "Unknown": "grey",
    }

    vulnerabilities = package_version["vulnerabilities"]["edges"]
    if vulnerabilities:
        sorted_vulns = sorted(vulnerabilities, key=lambda x: x["node"]["name"])

        table = Table(
            title="Vulnerabilities", show_header=True, header_style="bold green"
        )
        table.add_column("ID", style="dim", width=15)
        table.add_column("Details")
        table.add_column("Severity")

        for vuln in sorted_vulns:
            node = vuln["node"]
            severity_color = severity_to_color.get(node["severity"], "grey")
            table.add_row(
                node["name"],
                node["description"],
                f"[{severity_color}]{node['severity']}[/]",
            )

        console.print(table)
        console.print(
            f"Total vulnerabilities found: {len(vulnerabilities)}", style="bold yellow"
        )
    else:
        console.print("No vulnerabilities found.", style="bold green")


def json_formatter(results):
    print(json.dumps(results, indent=4))


@conan_command(
    group="Security",
    formatters={"text": display_vulnerabilities, "json": json_formatter},
)
def catalog(conan_api, parser, *args):
    """
    Check details for a specific package version.
    """
    parser.add_argument(
        "--catalog-url",
        required=True,
        help="GraphQL endpoint URL.",
    )
    parser.add_argument(
        "--username",
        help="Username for authentication. Optional.",
    )
    parser.add_argument(
        "--password",
        help="Password for authentication. Optional.",
    )
    parser.add_argument(
        "name",
        help="Package name.",
    )
    parser.add_argument(
        "version",
        help="Package version.",
    )

    args = parser.parse_args(*args)

    headers = {"Content-Type": "application/json", "Accept": "application/json"}

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
            "variables": {"name": args.name, "type": "conan", "version": args.version},
            "operationName": "packageVersionDetails",
        },
    )
    data_json = response.json()
    return data_json
