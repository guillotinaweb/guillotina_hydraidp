from setuptools import find_packages
from setuptools import setup


try:
    README = open('README.rst').read()
except IOError:
    README = ''
try:
    README += '\n\n' + open('CHANGELOG.rst').read()
except IOError:
    pass

setup(
    name='guillotina_hydraidp',
    version='1.0.3',
    description='Guillotina based identity provider for hydra',
    long_description=README,
    install_requires=[
        'guillotina>=4.2.10',
        'guillotina_authentication>=1.0.3',
        'argon2_cffi',
        'pypika'
    ],
    author='Nathan Van Gheem',
    author_email='vangheem@gmail.com',
    url='',
    packages=find_packages(exclude=['demo']),
    include_package_data=True,
    tests_require=[
        'pytest',
        'aioresponses'
    ],
    extras_require={
        'test': [
            'pytest',
            'aioresponses'
        ]
    },
    classifiers=[],
    entry_points={
    }
)
