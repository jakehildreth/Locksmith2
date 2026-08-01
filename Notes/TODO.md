* [ ] Test-IsBA is incomplete
* [ ] Convert EKUs, Safe Enrollees, Safe Writers, Safe Owners to enums?
* [ ] Add OwnerObjectClass property to LS2Issue, populate for ESC4o/ESC5o (resolve owner via PrincipalStore like IdentityReferenceClass), include in ESC4o/ESC5o Detailed format views
* [ ] Add CARole property to LS2Issue for ESC7a/ESC7m; Find-LS2VulnerableCA currently shoehorns CA role ('Administrators'/'Officers') into ActiveDirectoryRights, which also muddies LS2Issue.Matches() dedup semantics