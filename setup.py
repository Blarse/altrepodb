import codecs
from setuptools import setup, find_packages
from altrepodb import __version__


with codecs.open("README.md", encoding="utf-8") as f:
    README = f.read()

with codecs.open("CHANGELOG.md", encoding="utf-8") as f:
    CHANGELOG = f.read()

requirements = None
with open("requirements.txt", "r") as f:
    requirements = [line.rstrip() for line in f.readlines() if not line.startswith("-")]

setup(
    name="altrepodb",
    version=__version__,
    author="Danil Shein",
    author_email="dshein@altlinux.org",
    python_requires=">=3.7",
    packages=find_packages(exclude=["tests", ]),
    url="https://git.altlinux.org/gears/a/altrepodb.git",
    license="GNU GPLv3",
    description="ALTRepo Uploader",
    include_package_data=True,
    long_description="\n".join((README, CHANGELOG)),
    long_description_content_type="text/markdown",
    zip_safe=False,
    install_requires=requirements,
    keywords="altrepo altrepodb",
    scripts=[
        "bin/uploaderd",
        "bin/acl_loader",
        "bin/beehive_loader",
        "bin/bugzilla_loader",
        "bin/image_loader",
        "bin/iso_loader",
        "bin/package_loader",
        "bin/repocop_loader",
        "bin/repo_loader",
        "bin/spdx_loader",
        "bin/task_cleaner",
        "bin/task_loader",
        "bin/watch_loader",
    ],
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Natural Language :: English",
        "License :: OSI Approved :: GNU General Public License (GPLv3)",
        "Operating System :: POSIX",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
    ],
)
