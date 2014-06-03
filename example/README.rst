Example
=======

Let's say you have two accounts

development
  with account id 888888888888

staging
  with account id 999999999999

Then to sync these users you would::

  # export AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY for development
  iam_syncr development

  # export AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY for staging
  iam_syncr staging

And then you would have "ci-role" and "project-deploy-dev" in the
development account and a "project-deploy-stg" role in the staging account.

And the "ci-role" would be allowed to call STS:AssumeRole and become either of
the deploy roles.
