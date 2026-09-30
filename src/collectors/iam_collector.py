"""IAM Collector: Retrieves IAM users, roles, policies, and configurations from AWS or mock files."""

import json
import logging
from typing import Any, Dict, List, Optional
import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)


class IAMCollector:
    """Collects IAM state from AWS or local mock definitions."""

    def __init__(self, session: Optional[boto3.Session] = None, mock_file: Optional[str] = None):
        self.mock_file = mock_file
        self.session = session or boto3.Session()
        self._client = None if mock_file else self.session.client("iam")

    def collect_all(self) -> Dict[str, Any]:
        """Collect full IAM state: roles, users, customer managed policies."""
        if self.mock_file:
            return self._load_mock_data(self.mock_file)

        logger.info("Starting live AWS IAM state collection...")
        roles = self.get_roles()
        users = self.get_users()
        policies = self.get_customer_policies()

        return {
            "account_id": self._get_account_id(),
            "roles": roles,
            "users": users,
            "customer_policies": policies
        }

    def _get_account_id(self) -> str:
        try:
            sts = self.session.client("sts")
            return sts.get_caller_identity().get("Account", "unknown")
        except Exception:
            return "unknown"

    def _load_mock_data(self, file_path: str) -> Dict[str, Any]:
        logger.info(f"Loading mock IAM state from {file_path}")
        with open(file_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def get_roles(self) -> List[Dict[str, Any]]:
        """Fetch all IAM roles with attached policies, inline policies, and boundaries."""
        if self.mock_file:
            return self._load_mock_data(self.mock_file).get("roles", [])

        roles = []
        paginator = self._client.get_paginator("list_roles")
        for page in paginator.paginate():
            for role in page.get("Roles", []):
                role_name = role["RoleName"]
                # Skip AWS service-linked roles
                if role.get("Path", "").startswith("/aws-service-role/"):
                    continue

                role_data = {
                    "RoleName": role_name,
                    "Arn": role["Arn"],
                    "CreateDate": role["CreateDate"].isoformat() if hasattr(role["CreateDate"], "isoformat") else str(role["CreateDate"]),
                    "AssumeRolePolicyDocument": role.get("AssumeRolePolicyDocument", {}),
                    "PermissionsBoundary": role.get("PermissionsBoundary", {}).get("PermissionsBoundaryArn"),
                    "AttachedPolicies": self._get_role_attached_policies(role_name),
                    "InlinePolicies": self._get_role_inline_policies(role_name)
                }
                roles.append(role_data)
        return roles

    def _get_role_attached_policies(self, role_name: str) -> List[Dict[str, str]]:
        attached = []
        try:
            paginator = self._client.get_paginator("list_attached_role_policies")
            for page in paginator.paginate(RoleName=role_name):
                for pol in page.get("AttachedPolicies", []):
                    attached.append({
                        "PolicyName": pol["PolicyName"],
                        "PolicyArn": pol["PolicyArn"]
                    })
        except ClientError as e:
            logger.warning(f"Failed to list attached policies for role {role_name}: {e}")
        return attached

    def _get_role_inline_policies(self, role_name: str) -> Dict[str, Any]:
        inline = {}
        try:
            paginator = self._client.get_paginator("list_role_policies")
            for page in paginator.paginate(RoleName=role_name):
                for pol_name in page.get("PolicyNames", []):
                    doc = self._client.get_role_policy(RoleName=role_name, PolicyName=pol_name)
                    inline[pol_name] = doc.get("PolicyDocument", {})
        except ClientError as e:
            logger.warning(f"Failed to get inline policies for role {role_name}: {e}")
        return inline

    def get_users(self) -> List[Dict[str, Any]]:
        """Fetch all IAM users with attached policies, inline policies, groups, and MFA."""
        if self.mock_file:
            return self._load_mock_data(self.mock_file).get("users", [])

        users = []
        paginator = self._client.get_paginator("list_users")
        for page in paginator.paginate():
            for user in page.get("Users", []):
                user_name = user["UserName"]
                user_data = {
                    "UserName": user_name,
                    "Arn": user["Arn"],
                    "CreateDate": user["CreateDate"].isoformat() if hasattr(user["CreateDate"], "isoformat") else str(user["CreateDate"]),
                    "PermissionsBoundary": user.get("PermissionsBoundary", {}).get("PermissionsBoundaryArn"),
                    "Groups": self._get_user_groups(user_name),
                    "AttachedPolicies": self._get_user_attached_policies(user_name),
                    "InlinePolicies": self._get_user_inline_policies(user_name),
                    "MFADevices": self._get_user_mfa_devices(user_name)
                }
                users.append(user_data)
        return users

    def _get_user_groups(self, user_name: str) -> List[str]:
        groups = []
        try:
            res = self._client.list_groups_for_user(UserName=user_name)
            groups = [g["GroupName"] for g in res.get("Groups", [])]
        except ClientError as e:
            logger.warning(f"Failed to list groups for user {user_name}: {e}")
        return groups

    def _get_user_attached_policies(self, user_name: str) -> List[Dict[str, str]]:
        attached = []
        try:
            paginator = self._client.get_paginator("list_attached_user_policies")
            for page in paginator.paginate(UserName=user_name):
                for pol in page.get("AttachedPolicies", []):
                    attached.append({
                        "PolicyName": pol["PolicyName"],
                        "PolicyArn": pol["PolicyArn"]
                    })
        except ClientError as e:
            logger.warning(f"Failed to list attached policies for user {user_name}: {e}")
        return attached

    def _get_user_inline_policies(self, user_name: str) -> Dict[str, Any]:
        inline = {}
        try:
            paginator = self._client.get_paginator("list_user_policies")
            for page in paginator.paginate(UserName=user_name):
                for pol_name in page.get("PolicyNames", []):
                    doc = self._client.get_user_policy(UserName=user_name, PolicyName=pol_name)
                    inline[pol_name] = doc.get("PolicyDocument", {})
        except ClientError as e:
            logger.warning(f"Failed to get inline policy for user {user_name}: {e}")
        return inline

    def _get_user_mfa_devices(self, user_name: str) -> List[Dict[str, Any]]:
        mfa_devices = []
        try:
            res = self._client.list_mfa_devices(UserName=user_name)
            mfa_devices = res.get("MFADevices", [])
        except ClientError:
            pass
        return mfa_devices

    def get_customer_policies(self) -> List[Dict[str, Any]]:
        """Fetch all customer-managed policies and their active policy documents."""
        if self.mock_file:
            return self._load_mock_data(self.mock_file).get("customer_policies", [])

        policies = []
        try:
            paginator = self._client.get_paginator("list_policies")
            for page in paginator.paginate(Scope="Local"):
                for pol in page.get("Policies", []):
                    pol_arn = pol["Arn"]
                    ver_id = pol.get("DefaultVersionId")
                    doc = {}
                    if ver_id:
                        v_res = self._client.get_policy_version(PolicyArn=pol_arn, VersionId=ver_id)
                        doc = v_res.get("PolicyVersion", {}).get("Document", {})
                    policies.append({
                        "PolicyName": pol["PolicyName"],
                        "PolicyArn": pol_arn,
                        "DefaultVersionId": ver_id,
                        "PolicyDocument": doc
                    })
        except ClientError as e:
            logger.warning(f"Failed to list customer managed policies: {e}")
        return policies
