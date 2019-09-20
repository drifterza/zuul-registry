Zuul Registry
=============

This is a container image registry for use with the Zuul project
gating system.

The defining feature of this registry is support for shadowing images:
it allows you to upload a local version of an image to use instead of
an upstream version.  If you pull an image from this registry, it will
provide the local version if it exists, or the upstream if it does
not.

This makes it suitable for use in a Zuul-driven speculative image
pipeline.

The latest documentation for Zuul is published at:
https://zuul-ci.org/docs/

Getting Help
------------

There are two Zuul-related mailing lists:

`zuul-announce <http://lists.zuul-ci.org/cgi-bin/mailman/listinfo/zuul-announce>`_
  A low-traffic announcement-only list to which every Zuul operator or
  power-user should subscribe.

`zuul-discuss <http://lists.zuul-ci.org/cgi-bin/mailman/listinfo/zuul-discuss>`_
  General discussion about Zuul, including questions about how to use
  it, and future development.

You will also find Zuul developers in the `#zuul` channel on Freenode
IRC.

Contributing
------------

To browse the latest code, see: https://opendev.org/zuul/zuul-registry
To clone the latest code, use `git clone https://opendev.org/zuul/zuul-registry`

Bugs are handled at: https://storyboard.openstack.org/#!/project/zuul/zuul-registry

Suspected security vulnerabilities are most appreciated if first
reported privately following any of the supported mechanisms
described at https://zuul-ci.org/docs/zuul/user/vulnerabilities.html

Code reviews are handled by gerrit at https://review.opendev.org

After creating a Gerrit account, use `git review` to submit patches.
Example::

    # Do your commits
    $ git review
    # Enter your username if prompted

Join `#zuul` on Freenode to discuss development or usage.

License
-------

Zuul-registry is free software licensed under the General Public
License, version 3.0.

Python Version Support
----------------------

Zuul requires Python 3. It does not support Python 2.
