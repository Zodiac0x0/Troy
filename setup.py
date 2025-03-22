from setuptools import setup, find_packages

setup(
    name="troy-scanner",
    version="1.2",
    description="A web application security scanner for XSS and Path Traversal",
    author="Omar Islam",
    url="https://github.com/Zodiac0x0/Troy",
    packages=find_packages(),  
    install_requires=["requests>=2.28.0"],
    package_data= {
        'troy' : ['payloads/*.txt']
    },
    entry_points={
        "console_scripts": [
            "troy = troy.Troy:main"
        ]
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
)