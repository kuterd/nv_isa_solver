from setuptools import setup, find_packages

setup(
    name="nv_isa_solver",
    version="0.1",
    packages=find_packages(),
    install_requires=["tqdm"],
    entry_points={
        "console_scripts": [
            "nv-isa-solver = nv_isa_solver.instruction_solver:main",
            "nv-isa-solver-scan = nv_isa_solver.scan_disasm:main",
            "nv-isa-solver-mutate = nv_isa_solver.mutate_opcodes:main",
        ],
    },
    author="Kuter Dinel",
    author_email="kuterdinel@gmail.com",
    description="Nvidia Instruction Set Documentation Generator",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/kuterd/nv_isa_solver",
    license="MIT",  # Example license
)
