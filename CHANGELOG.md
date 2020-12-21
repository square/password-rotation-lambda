# square/password-rotation-lambda Changelog

## v2.0

### v2.0.2 (2020-12-21)

* Fix rollback
* Fix concurrent execution by removing cache
* Improve log and debug output

### v2.0.1 (2020-12-17)

* Fix panic on nil RDS Endpoint (when db instance is being provisioned) in mysql/setter.go

### v2.0.0 (2020-11-02)

* Add map[string]string to Handler() return

---

## v1.0

### v1.0.1 (2020-10-27)

* Fix db instance flags/errors between runs

### v1.0.0 (2020-10-15)

* First GA release
