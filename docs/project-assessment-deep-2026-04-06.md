# Deep Project Assessment

Date: 2026-04-06

## Summary

The project is functionally rich and operationally mature, but the main technical risks are concentrated in architecture, admin-surface security, schema consistency, and maintainability. The most urgent conclusions from the deep review are:

- `app/main.py` remains a God Object and still blocks safe refactoring.
- The admin surface needs authentication and CSRF protection before further expansion.
- SQL/ORM schema drift and lack of PostgreSQL integration testing are structural correctness risks.
- Inline HTML generation and dict-based dependency wiring reduce readability and safety.
- Documentation is strong, but product UX and onboarding still need simplification.

## Top Priority Problems

1. Missing authentication and authorization for `/admin`.
2. Missing CSRF protection for admin HTML flows.
3. Oversized `app/main.py` and `app/routes/ops.py`.
4. Dual schema ownership between `database/init/*` and ORM/Alembic.
5. Inline HTML rendering in Python f-strings instead of templates.
6. Missing PostgreSQL integration coverage for SQL-native behavior.
7. Unsafe runtime `SECRET_KEY` auto-generation path in container startup.
8. No API versioning.
9. No OpenAPI contract.
10. Missing `.dockerignore`.

## Milestone Mapping

- `1.4.2`: security and runtime hardening
- `1.5.0`: core modularization and template extraction
- `1.5.1`: database convergence and PostgreSQL validation
- `1.6.0`: API and configuration modernization
- `1.6.1`: integration adapter boundary and runtime resilience
- `1.7.0`: product UX and scope rationalization

## Notes

- GitHub milestones were updated to mirror this plan.
- The roadmap was reordered so that critical security issues are handled before deeper product-facing changes.
