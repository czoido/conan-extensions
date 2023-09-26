import os

from conan.api.output import ConanOutput
from conan.cli import make_abs_path
from conan.cli.args import common_graph_args, validate_common_graph_args
from conan.cli.command import conan_command
from conan.cli.formatters.graph import format_graph_json
from conan.cli.printers import print_profiles
from conan.cli.printers.graph import print_graph_packages, print_graph_basic
from conan.tools.files import copy, rmdir


@conan_command(group="Compliance", formatters={"json": format_graph_json})
def collect_licenses(conan_api, parser, *args):
    """
    Contruct the dependency graph specified in a given recipe (conanfile.py or conanfile.txt),
    finds license files and collects them into a folder (/licences) and summaryzes the results
    on a licenses.txt file in the same folder.
    """

    out = ConanOutput("deployer(licenses)")
    # Everything based in install command and in conan-extensions\extensions\deployers\licenses.py
    common_graph_args(parser)
    parser.add_argument("-g", "--generator", action="append",
                        help='Generators to use')
    parser.add_argument("-of", "--output-folder",
                        help='The root output folder for generated and build files')
    parser.add_argument("-d", "--deployer", action="append",
                        help='Deploy using the provided deployer to the output folder')
    parser.add_argument("--deployer-folder",
                        help="Deployer output folder, base build folder by default if not set")
    parser.add_argument("--build-require", action='store_true', default=False,
                        help='Whether the provided path is a build-require')
    args = parser.parse_args(*args)
    validate_common_graph_args(args)

    # basic paths
    cwd = os.getcwd()
    path = conan_api.local.get_conanfile_path(
        args.path, cwd, py=None) if args.path else None

    # Basic collaborators: remotes, lockfile, profiles
    remotes = conan_api.remotes.list(args.remote) if not args.no_remote else []
    overrides = eval(
        args.lockfile_overrides) if args.lockfile_overrides else None
    lockfile = conan_api.lockfile.get_lockfile(lockfile=args.lockfile, conanfile_path=path, cwd=cwd,
                                               partial=args.lockfile_partial, overrides=overrides)
    profile_host, profile_build = conan_api.profiles.get_profiles_from_args(
        args)
    # I keep this because I asume the information could be useful, as it is in the install command
    print_profiles(profile_host, profile_build)

    # Graph computation (without installation of binaries)
    # I keep this full part, because is requested in the assignment
    gapi = conan_api.graph
    if path:
        deps_graph = gapi.load_graph_consumer(path, args.name, args.version, args.user, args.channel,
                                              profile_host, profile_build, lockfile, remotes,
                                              args.update, is_build_require=args.build_require)
    else:
        deps_graph = gapi.load_graph_requires(args.requires, args.tool_requires, profile_host,
                                              profile_build, lockfile, remotes, args.update)
    print_graph_basic(deps_graph)
    deps_graph.report_graph_error()
    gapi.analyze_binaries(deps_graph, args.build, remotes,
                          update=args.update, lockfile=lockfile)
    print_graph_packages(deps_graph)

    # Installation of binaries and consumer generators
    # I keep this for convenience, this way I dont have to install and then run the command
    # Also needed for copy to work propertly
    conan_api.install.install_binaries(deps_graph=deps_graph, remotes=remotes)

    conanfile = deps_graph.root.conanfile
    files = []

    # I will create the folder with base in the current directory
    tmp_dir = os.path.join(cwd, "licenses")
    if os.path.exists(tmp_dir):
        rmdir(conanfile, tmp_dir)

    for r, d in conanfile.dependencies.items():
        if d.package_folder is None:
            continue
        search_dir = os.path.join(d.package_folder, "licenses")
        if not os.path.isdir(search_dir):
            continue
        for f in os.listdir(search_dir):
            src = os.path.join(search_dir)
            dst = os.path.join(tmp_dir, str(d.ref))
            out.debug(src)
            out.debug(dst)
            copy(conanfile, f, src, dst)
            files.append(os.path.join(str(d.ref), f))
    if os.path.exists(tmp_dir):
        with open(cwd + '\\licenses\\licenses.txt', 'w') as f:
            for license_file in files:
                f.write(license_file + '\n')
    # The next step should be to do a more intense search, no just licenses as expressed in the assignment (license(s)/*, LICENSE.*, Copyright.*, etc)
