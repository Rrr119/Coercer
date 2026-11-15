#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse

from coercer.core.Reporter import create_reporter


def make_options(**overrides):
    defaults = dict(
        verbose=False,
        debug=False,
        log_file=None,
        minimum_log_level=0,
        disable_escape_codes=True,
    )
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


# The reporter singleton must exist before any coercer module importing
# "from coercer.core.Reporter import reporter" is loaded.
create_reporter(make_options(), False)
