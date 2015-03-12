from six.moves.urllib import parse
from datadiff import diff
import json

class AmazonDocuments(object):
    def compare_trust_document(self, role_info, trust_document):
        """Say whether the provided trust document is the same as the one in the role_info"""
        if not role_info or not role_info.get("role", {}).get("assume_role_policy_document"):
            return []

        unquoted = parse.unquote(role_info["role"]["assume_role_policy_document"])
        return self.compare_two_documents(unquoted, trust_document)

    def compare_two_documents(self, doc1, doc2):
        """Compare two documents by converting them into json objects and back to strings and compare"""
        try:
            first = json.loads(doc1)
        except (ValueError, TypeError):
            return

        try:
            second = json.loads(doc2)
        except (ValueError, TypeError):
            return

        # Ordering the principals because the ordering amazon gives me hates me
        def sort_statement(statement):
            for principal in (statement.get("Principal", None), statement.get("NotPrincipal", None)):
                if principal:
                    for principal_type in ("AWS", "Federated", "Service"):
                        if principal_type in principal and type(principal[principal_type]) is list:
                            principal[principal_type] = sorted(principal[principal_type])
        def sort_key(statement, key):
            if key in statement and type(statement[key]) is list:
                statement[key] = sorted(statement[key])
        for document in (first, second):
            if "Statement" in document:
                if type(document["Statement"]) is dict:
                    sort_statement(document["Statement"])
                    sort_key(document["Statement"], "Action")
                    sort_key(document["Statement"], "NotAction")
                    sort_key(document["Statement"], "Resource")
                    sort_key(document["Statement"], "NotResource")
                else:
                    for statement in document["Statement"]:
                        sort_statement(statement)
                        sort_key(statement, "Action")
                        sort_key(statement, "NotAction")
                        sort_key(statement, "Resource")
                        sort_key(statement, "NotResource")

        difference = diff(first, second, fromfile="current", tofile="new").stringify()
        if difference:
            lines = difference.split('\n')
            if not first or not second or any(line.strip().startswith("@@") and line.strip().endswith("@@") for line in lines):
                for line in lines:
                    yield line

