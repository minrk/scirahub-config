#!/bin/bash
PREFIX=/usr/local/libexec/jupyterhub
source $PREFIX/bin/activate
exec jupyterhub "$@"
