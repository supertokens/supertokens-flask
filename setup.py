from setuptools import setup, find_packages
from os import path

here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(here, "README.md"), mode="r", encoding="utf-8") as f:
    long_description = f.read()

extras_require = {
    'dev': ([
        'pytest',
        'flask',
        'jsonschema',
        'flake8',
        'autopep8',
        'pyyaml',
        'flask-cors'
    ])
}

setup(
    name="supertokens_flask",
    version="1.4.1",
    author="SuperTokens",
    license="Apache 2.0",
    author_email="team@supertokens.io",
    description="SuperTokens session management solution for flask",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/supertokens/supertokens-flask",
    packages=find_packages(exclude=["tests", ]),
    classifiers=[
        "Framework :: Flask",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Intended Audience :: Developers",
        "Topic :: Internet :: WWW/HTTP :: Session",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    keywords="",
    install_requires=[
        "flask",
        "requests",
        "pycryptodome",
    ],
    python_requires='>=3.7',
    extras_require=extras_require
)
