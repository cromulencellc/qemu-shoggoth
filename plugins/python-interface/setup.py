import setuptools

with open("README.md", "r") as fh:
    long_desc = fh.read()

setuptools.setup(
    name="pyqemu",
    version="0.1",
    author="Cromulence LLC",
    author_email="shoggoth@cromulence.com",
    description="Python interface for plugins to interface with Shoggoth",
    long_description=long_desc,
    long_description_content_type="text/markdown",
    url="https://ghithub.com/cromulencellc/qemu-shoggoth",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU Affero General Public License v3",
        "Operating System :: POSIX :: Linux",
    ],
    python_requires='>=3.6',
)

