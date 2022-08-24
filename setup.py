import setuptools
from smbcrawler._version import __version__

setuptools.setup(
    name='smbcrawler',
    version=__version__,
    author='Adrian Vollmer',
    author_email='adrian.vollmer@syss.de',
    url='https://github.com/SySS-Research/smbcrawler',
    description='Search SMB shares for interesting files',
    long_description=open('README.md', 'r').read(),
    long_description_content_type='text/markdown',
    packages=setuptools.find_packages(),
    entry_points={
        'console_scripts': [
            'smbcrawler=smbcrawler.__main__:main'
        ],
    },
    install_requires=[
        'impacket>=0.9.20',
        'python-libnmap',
        'lxml',
        'pdftotext',
        'python-magic',
    ],
    python_requires='>=3.5',
    tests_require=[
        'pytest',
        'pyexpect',
    ],
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
    ],
)
