IAM syncr
=========

A tool for keeping iam roles synced.

Installation
============

Just use pip::

   pip install iam_syncr

Usage
=====

You make a folder for each amazon account you have and you put in there files
that define the roles you want to define in that account.

You then run::

   iam_syncr <folder>

It will find the roles you have defined and ensure they exist and only have the
policies you have defined.

It will leave alone other roles in your account.

Note that for the roles you have defined, it will remove any policies that don't
match what you have.

It is up to you to put the necessary amazon credentials in your environment via
AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY.

Format
======

accounts.yaml
   The script will look for an accounts.yaml in the directory above the folder
   you specified. This is expected to be a mapping of {account_name:account_id}
   where account_id is the 12 digit id without hyphens for each amazon account.

   The script will use these values to both check that the credentials you
   supplied is for the account you are syncing and will also use the values if
   you specify you account names in the policies.

Any yaml file in the specified folder
   Currently only supports files with a "roles" or "remove_roles" definition in it.

Yaml Configuration
==================

The yaml looks something like::

    ---

    templates:
      <template_name>: template

    roles:
      <role_name>:
         use: <template_name>

         description: <optional>

         make_instance_profile: <boolean saying whether to make an instance profile with this role in it>

         allow_to_assume_me: [<assume_role_statements>]
         disallow_to_assume_me: [<assume_role_statements>]

         permission: [<permission_statements>]
         deny_permission: [<permission_statemnt> where "Effect" is set to "Deny"]
         allow_permission: [<permission_statemnt> where "Effect" is set to "Allow"]

   remove_role:
      - <role_name>
      - <role_name>
      - ...

Where ``<assume_role_statement>`` can be:

``{service: ec2}``
   Sets the principle to ``{"Service": "ec2.amazonaws.com"}``

   You'll want to do this if you want to use metdata credentials on an ec2 box

``<iam_specifier>``
   See below, it specifies an iam resource

   Basically allows the iam role specified to call assume role to be this role.

``{federated: <string>}``
   Sets the principle to ``{"Federated": <string>}``

   With an ``Action`` of ``AssumeRoleWithSAML``.

``{federated: <iam_specifier>}``
   Sets the principle to ``{"Federated": <expanded iam specifier>}``

   With an ``Action`` of ``AssumeRoleWithSAML``.

Anything in the dictionary starting with an upper case character is included as
is in the statement.

Also, the difference between ``allow_to_assume_me`` and ``disallow_to_assume_me``
is one sets ``Principle`` in the trust document, whereas the other sets ``NotPrinciple``.

And ``<permission_statement>`` can be:

``{"action": <action>, resource: <resource>, "allow":<True|False>}``
   Allows ``<action>`` for specified ``<resource>`` (string or list of strings)

   "allow" will override any default allow or "Effect" you specify

   And anything starting with an upper case character is included in the
   statement as is.

Where ``action`` and ``resource`` can be ``notaction`` and ``notresource``.

And ``<resource>`` can be:

A single string
   Placed in the policy as a list of that one string

A list of ``<resource>``
   Placed in the policy with each ``<resource>`` expanded

``<iam_specifier>``
   See below, it specifies an iam resource

``{"s3": <s3_specifier>}``
   "arn:aws:s3:::<s3_specifier>

``{"s3": [<s3_specifier>, <s3_specifier>, ...]}``
   ["arn:aws:s3:::<s3_specifier>", "arn:aws:s3:::<s3_specifier>", ...]

Where ``<iam_specifer>`` can be:

``{"iam":"__self__"}``
   arn for the role/user this policy is being given to

``{"iam":<specifier>, "account":<account>"}``
   "arn:aws:iam::<account>:<specifier>"

   Where account is retrieved from our accounts dictionary from accounts.yaml

Dry Run
=======

You can use the ``--dry-run`` option to make iam_syncr tell you what changes will
be made without making those changes.

It will print out the changes to stdout.

Lines starting with "+" indicate additions, lines starting with "-" indicate
deletions and lines starting with "M" indicate modifications.

Modifications are followed by an indented diff of the differences to be made.

The Future
==========

In order of importance:

* More Tests

