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
    version='1.0.1.dev0',
    description='Guillotina based identity provider for hydra',
    long_description=README,
    install_requires=[
        'guillotina>=4.2.10',
        'guillotina_authentication',
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
    ],
    extras_require={
        'test': [
            'pytest'
        ]
    },
    classifiers=[],
    entry_points={
    }
)
