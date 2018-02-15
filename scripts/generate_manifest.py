#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys

import json
import yaml

import jinja2
from jinja2.runtime import StrictUndefined


def merge_dicts(a, b):
    if not (isinstance(a, dict) and isinstance(b, dict)):
        raise ValueError("Error merging variables: '{}' and '{}'".format(
            type(a).__name__, type(b).__name__
        ))

    result = a.copy()
    for key, val in b.items():
        if isinstance(result.get(key), dict):
            result[key] = merge_dicts(a[key], b[key])
        else:
            result[key] = val

    return result


def template_string(string, variables, templates_path=None):
    jinja_env = jinja2.Environment(
        trim_blocks=True,
        undefined=StrictUndefined,
    )

    template = jinja_env.from_string(string)
    return template.render(variables)


def load_manifest(manifest_file):
    with open(manifest_file) as f:
        return f.read()


def load_variables(vars_files):
    variables = {}
    for vars_file in vars_files:
        with open(vars_file) as f:
            variables = merge_dicts(variables, yaml.load(f))

    return {
        k: json.dumps(v) if isinstance(v, (dict, list)) else v
        for k, v in variables.items()
    }


def paas_manifest(manifest_file, *vars_files):
    """Generate a PaaS manifest file from a Jinja2 template"""

    manifest = load_manifest(manifest_file)
    variables = load_variables(vars_files)

    return template_string(manifest, variables)


if __name__ == "__main__":
    print(paas_manifest(*sys.argv[1:]))
