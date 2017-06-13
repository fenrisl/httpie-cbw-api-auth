from setuptools import setup
try:
    import multiprocessing
except ImportError:
    pass

setup(
    name='httpie-cbw-api-auth',
    description='CyberWatch ApiAuth plugin for HTTPie.',
    long_description=open('README.md').read().strip(),
    version='0.0.2',
    author='CyberWatch SAS',
    author_email='contact@cyberwatch.fr',
    license='MIT',
    url='https://gitlab.cbw.io/CyberwatchTeam/httpie-cbw-api-auth',
    py_modules=['httpie_cbw_api_auth'],
    zip_safe=False,
    entry_points={
        'httpie.plugins.auth.v1': [
            'httpie_cbw_api_auth = httpie_cbw_api_auth:CbwApiAuthPlugin'
        ]
    },
    install_requires=[
        'httpie>=0.9.3,<=0.9.6'
    ]
)
