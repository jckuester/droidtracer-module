#!/usr/bin/env python

from distutils.core import setup, Extension

opts = ['-O', '-nodefaultctor']
include = ['../include']

netlink_capi = Extension('netlink/_capi',
                         sources = ['netlink/capi.i'],
			 include_dirs = include,
			 swig_opts = opts,
			 libraries = ['nl-3'],
			)

route_capi = Extension('netlink/route/_capi',
                         sources = ['netlink/route/capi.i'],
			 include_dirs = include,
			 swig_opts = opts,
			 libraries = ['nl-3', 'nl-route-3'],
			)

setup(name = 'netlink',
      version = '1.0',
      description = 'Python wrapper for netlink protocols',
      author = 'Thomas Graf',
      author_email = 'tgraf@suug.ch',
      ext_modules = [netlink_capi, route_capi],
      packages = ['netlink', 'netlink.route', 'netlink.route.links',
      		  'netlink.route.qdisc'],
     )
