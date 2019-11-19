# Penetration Testing Guide

## Getting Started

Install sphinx and the "Read The Docs" theme:

```bash
$ pip install sphinx sphinx_rtd_theme
```

## Contributing

I've tried to stick to a layout throughout (early on I did not, if you see pages that don't match the style I'm about to describe, feel free to fix them).

**Section Headings**

The page title should be at the top of the page and use the following syntax. Note that the #'s must appear above and below the title, and must span the width of the title.

```
##########
Page Title
##########
```

Sections, subsections, etc use a similar syntax, but do not require an overline:

```
Section
=======

Subsection
----------

Subsubsection
^^^^^^^^^^^^^
```

If anything lower than the subsubsection is required, it is suggested that bold text is used.

**Code Examples**

Code blocks can be placed like so:

```
.. code-block:: bash

    code goes here
```

If possible, avoid showing prompt characters (e.g. $, #, or C:\>) unless necessary for the example.

For inline code, use:

```
:code:`inline code goes here`
```

**Additional Markup**

There is a very useful basic guide to Sphinx/reStructuredText here: http://www.sphinx-doc.org/en/master/usage/restructuredtext/basics.html

**Compiling**

How to compile after making alterations:

```bash
$ pip install sphinx sphinx_rtd_theme
$ make clean && make html
```

The compiled html will be in the _build directory.
