import tempfile
import textwrap
import os

import pytest

from tools import save, run


@pytest.fixture(autouse=True)
def conan_test():
    old_env = dict(os.environ)
    env_vars = {"CONAN_HOME": tempfile.mkdtemp(suffix='conans')}
    os.environ.update(env_vars)
    current = tempfile.mkdtemp(suffix="conans")
    cwd = os.getcwd()
    os.chdir(current)
    try:
        yield
    finally:
        os.chdir(cwd)
        os.environ.clear()
        os.environ.update(old_env)


def test_collect_licenses():
    run("conan profile detect")
    repo = os.path.join(os.path.dirname(__file__), "..")
    run(f"conan config install {repo}")
    conanfile = textwrap.dedent("""
        import os

        from conan import ConanFile
        from conan.tools.cmake import cmake_layout
        from conan.tools.files import copy


        class ImGuiExample(ConanFile):
            settings = "os", "compiler", "build_type", "arch"
            generators = "CMakeDeps", "CMakeToolchain"

            def requirements(self):
                self.requires("imgui/1.89.4")
                self.requires("glfw/3.3.8")
                self.requires("glew/2.2.0")

            def generate(self):
                copy(self, "*glfw*", os.path.join(self.dependencies["imgui"].package_folder,
                    "res", "bindings"), os.path.join(self.source_folder, "bindings"))
                copy(self, "*opengl3*", os.path.join(self.dependencies["imgui"].package_folder,
                    "res", "bindings"), os.path.join(self.source_folder, "bindings"))

            def layout(self):
                cmake_layout(self)
        """)

    save("conanfile.py", conanfile)
    run("conan compliance:collect-licenses conanfile.py")

    # Test just for convenience, the next step should be to make it useful (useful assert, more conanfiles, posible errors)
    assert 0 == 0
