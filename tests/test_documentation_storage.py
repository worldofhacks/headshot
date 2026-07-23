"""Database-enforced Documentation and regression trust boundaries."""

from __future__ import annotations

from sqlalchemy import Engine, text


def test_documentation_tables_are_append_only_and_data_constrained(
    migrated_db: Engine,
) -> None:
    with migrated_db.connect() as connection:
        tables = {
            row[0]
            for row in connection.execute(
                text(
                    "SELECT tablename FROM pg_tables WHERE schemaname = 'public' "
                    "AND tablename IN ('vuln_reports','regression_dispositions')"
                )
            )
        }
        triggers = {
            row[0]
            for row in connection.execute(
                text(
                    "SELECT tgname FROM pg_trigger WHERE NOT tgisinternal "
                    "AND tgrelid IN ('vuln_reports'::regclass, "
                    "'regression_dispositions'::regclass)"
                )
            )
        }

    assert tables == {"vuln_reports", "regression_dispositions"}
    assert triggers == {
        "trg_vuln_reports_append_only",
        "trg_regression_dispositions_append_only",
    }


def test_documentation_payload_projection_and_admission_proof_are_db_constrained(
    migrated_db: Engine,
) -> None:
    required = {
        "ck_vuln_reports_payload_projection",
        "ck_vuln_reports_critical_publication",
        "ck_regression_dispositions_payload_projection",
        "ck_regression_dispositions_admission_proof",
    }
    with migrated_db.connect() as connection:
        constraints = {
            row[0]
            for row in connection.execute(
                text(
                    "SELECT conname FROM pg_constraint WHERE contype = 'c' "
                    "AND conrelid IN ('vuln_reports'::regclass, "
                    "'regression_dispositions'::regclass)"
                )
            )
        }

    assert required <= constraints


def test_documentation_database_roles_enforce_least_privilege(migrated_db: Engine) -> None:
    expected = {
        "headshot_runner": {"SELECT": True, "INSERT": True},
        "headshot_web": {"SELECT": True, "INSERT": False},
        "headshot_redteam": {"SELECT": False, "INSERT": False},
        "headshot_judge": {"SELECT": False, "INSERT": False},
    }
    with migrated_db.connect() as connection:
        for role, privileges in expected.items():
            for table in ("vuln_reports", "regression_dispositions"):
                for privilege, allowed in privileges.items():
                    actual = connection.execute(
                        text("SELECT has_table_privilege(:role, :table, :privilege)"),
                        {"role": role, "table": table, "privilege": privilege},
                    ).scalar_one()
                    assert actual is allowed
                for privilege in ("UPDATE", "DELETE", "TRUNCATE"):
                    actual = connection.execute(
                        text("SELECT has_table_privilege(:role, :table, :privilege)"),
                        {"role": role, "table": table, "privilege": privilege},
                    ).scalar_one()
                    assert actual is False
