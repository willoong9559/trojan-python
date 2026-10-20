"""Compatibility entry point for older pip/setuptools combinations."""

from setuptools import find_packages, setup


setup(
    name="trojan-grpc-simple",
    version="0.1.0",
    description="A small asyncio Trojan-over-gRPC CONNECT server",
    python_requires=">=3.9",
    packages=find_packages(),
    install_requires=["h2>=4.1,<5"],
    entry_points={"console_scripts": ["trojan-grpc-server=trojan_grpc.server:main"]},
)
