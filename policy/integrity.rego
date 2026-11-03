# METADATA
# title: bootc derived-image integrity
# description: >-
#   Fails when an image built FROM a hardened base changes, removes, overrides or shadows
#   anything the base protects. Input comes from scripts/flatten-syft.py; configuration
#   from data.integrity (data/protected.yaml) and data.exceptions (data/exceptions.yaml).
package main

cfg := data.integrity

base := input.base

image := input.image

# File attributes that must match the base. Layer is compared separately.
fields := ["type", "mode", "uid", "gid", "sha256", "link"]

# ---------------------------------------------------------------------------
# Layering. If the base's layers are an unchanged prefix of the image's layers, every
# file the derived build wrote carries a layer ID outside the base. Squashed or rechunked
# images lose that attribution; content comparison still applies.

layered if {
	n := count(base.layers)
	n > 0
	count(image.layers) >= n
	array.slice(image.layers, 0, n) == base.layers
}

base_layers contains l if some l in base.layers

# With require_layered, an image that isn't layered on the base fails instead of only
# losing the 'touched' checks.
default require_layered := false

require_layered := cfg.require_layered

not_layered_msg := "base layers are not an unchanged prefix of the image's layers (squashed, rechunked, or built FROM a different base digest)"

# ---------------------------------------------------------------------------
# What is protected. Every protected path must look exactly as it does in the base,
# where "absent" is a state too: a protected path the base lacks must stay absent.

# Files the base installs from a protected RPM.
package_paths contains p if {
	some name in cfg.protected_packages
	some p in base.packages[name]
	base.files[p]
}

protected contains p if some p in package_paths

protected contains p if some p in cfg.protected_files

# The same file name in a higher-precedence directory replaces the protected file
# (systemd-style config, PATH order). Shadow paths must match the base, which usually
# means they must not exist.
protected contains shadow if {
	some p in protected_sources
	some from, targets in cfg.shadows
	startswith(p, from)
	some target in targets
	shadow := concat("", [target, substring(p, count(from), -1)])
}

protected_sources contains p if {
	some p in package_paths
}

protected_sources contains p if {
	some p in cfg.protected_files
	base.files[p]
}

# systemd units among the protected files, by unit name.
protected_units contains name if {
	some p in protected_sources
	startswith(p, "/usr/lib/systemd/system/")
	name := substring(p, count("/usr/lib/systemd/system/"), -1)
	not contains(name, "/")
	regex.match(`\.(service|socket|timer|path|mount|target)$`, name)
	base.files[p].type == "RegularFile"
}

# Enablement symlinks the base ships for protected units (removing one disables the unit),
# including instances of protected templates (worker@one.service for worker@.service).
protected contains p if {
	some p, f in base.files
	f.type == "SymbolicLink"
	regex.match(`^/(etc|usr/lib)/systemd/system/[^/]+\.(wants|requires)/[^/]+$`, p)
	protected_unit_name(basename(p))
}

protected_unit_name(name) if name in protected_units

protected_unit_name(name) if template_of(name) in protected_units

# Sealed directories: nothing may be added, changed or removed underneath.
sealed_dirs contains dir_prefix(d) if some d in cfg.sealed_dirs

# Directories systemd loads units and drop-ins from that can come from the image, highest
# precedence first. /run is empty at boot.
unit_dirs := [
	"/etc/systemd/system.control/",
	"/etc/systemd/system/",
	"/etc/systemd/system.attached/",
	"/usr/local/lib/systemd/system/",
	"/usr/lib/systemd/system/",
]

# A unit of the same name in any of them replaces or masks a protected unit.
protected contains concat("", [dir, unit]) if {
	some unit in protected_units
	some dir in unit_dirs
}

# Drop-ins for protected units can rewrite ExecStart= or add Condition*= lines.
sealed_dirs contains concat("", [dir, name, "/"]) if {
	some unit in protected_units
	some name in dropin_names(unit)
	some dir in unit_dirs
}

# The drop-in directories systemd reads for a unit: its own, one per dash-separated prefix
# of its name (falcon-sensor.service also reads falcon-.service.d/), and one for every unit
# of its type (service.d/).
dropin_names(unit) := names if {
	parts := split(unit, ".")
	type := parts[count(parts) - 1]
	words := split(trim_suffix(unit, concat("", [".", type])), "-")
	prefixes := {concat("", [concat("-", array.slice(words, 0, k)), "-.", type, ".d"]) |
		some k, _ in words
		k > 0
	}
	names := prefixes | {concat("", [unit, ".d"]), concat("", [type, ".d"])}
}

# Instances of a protected template can have their own unit file (worker@one.service) and
# drop-ins (worker@one.service.d/), which systemd reads in addition to the template's.
template_prefixes contains concat("", [dir, substring(unit, 0, indexof(unit, "@") + 1)]) if {
	some unit in protected_units
	contains(unit, "@.")
	some dir in unit_dirs
}

watched contains p if {
	some prefix in template_prefixes
	some p, _ in base.files
	startswith(p, prefix)
}

watched contains p if {
	some prefix in template_prefixes
	some p, _ in image.files
	startswith(p, prefix)
}

watched contains p if some p in protected

watched contains p if {
	some d in sealed_dirs
	some p, _ in base.files
	startswith(p, d)
}

watched contains p if {
	some d in sealed_dirs
	some p, _ in image.files
	startswith(p, d)
}

# The directory entries themselves (catches chmod/chown or replacing them with symlinks).
watched contains p if {
	some d in (sealed_dirs | appendable_prefixes)
	p := trim_suffix(d, "/")
	base.files[p]
}

# Appendable directories: files the base ships are protected; new files are allowed only
# when they are direct children whose names match the directory's pattern.
appendable_prefixes contains dir_prefix(a.dir) if some a in cfg.appendable_dirs

watched contains p if {
	some d in appendable_prefixes
	some p, _ in base.files
	startswith(p, d)
}

# ---------------------------------------------------------------------------
# Findings

findings contains finding(p, "added", image.files[p].layer, "not present in the base image") if {
	some p in watched
	not base.files[p]
	image.files[p]
}

findings contains finding(p, "deleted", "", "present in the base image but missing") if {
	some p in watched
	base.files[p]
	not image.files[p]
}

findings contains finding(p, "modified", a.layer, sprintf("changed %s", [concat(", ", changed)])) if {
	some p in watched
	b := base.files[p]
	a := image.files[p]
	changed := [k | some k in fields; b[k] != a[k]]
	count(changed) > 0
}

# Rewritten with identical content. Directories are skipped because adding any entry to a
# directory rewrites its directory entry. This also catches changes syft does not record,
# such as SELinux labels and other xattrs.
findings contains finding(p, "touched", a.layer, "rewritten by the derived build; contents match, but attributes not compared here (SELinux label, xattrs) may differ") if {
	layered
	some p in watched
	b := base.files[p]
	a := image.files[p]
	a.type != "Directory"
	every k in fields { b[k] == a[k] }
	not a.layer in base_layers
}

findings contains finding(p, "added", f.layer, sprintf("name not allowed in %s (allowed: %s)", [a.dir, a.allow])) if {
	some a in cfg.appendable_dirs
	d := dir_prefix(a.dir)
	some p, f in image.files
	startswith(p, d)
	not base.files[p]
	not p in watched
	not allowed_name(substring(p, count(d), -1), a.allow)
}

allowed_name(name, pattern) if {
	not contains(name, "/")
	regex.match(pattern, name)
}

# A symlink at a sealed or appendable directory, or at any directory above a watched path,
# moves the contents somewhere the check doesn't look: /etc/systemd/system/agent.service.d
# pointing at /opt/overrides. Symlinks the base already has are fine.
guarded_dirs := {trim_suffix(d, "/") | some d in (sealed_dirs | appendable_prefixes)}

redirect_candidates contains d if some d in guarded_dirs

redirect_candidates contains a if {
	some p in (guarded_dirs | watched)
	some a in ancestors(p)
}

findings contains finding(p, kind, f.layer, sprintf("symlink to %s redirects a protected location", [f.link])) if {
	some p in redirect_candidates
	not p in watched
	f := image.files[p]
	f.type == "SymbolicLink"
	not base_has_same(p, f)
	kind := redirect_kind(p)
}

redirect_kind(p) := "modified" if base.files[p]

redirect_kind(p) := "added" if not base.files[p]

base_has_same(p, f) if {
	b := base.files[p]
	every k in fields { b[k] == f[k] }
}

# Forbidden packages fail whenever the image has them installed, even if the base does too.
# The finding's path is the package name, so exceptions match on it.
findings contains finding(name, "forbidden", "", "package must not be installed") if {
	some name in cfg.forbidden_packages
	image.packages[name]
}

# ---------------------------------------------------------------------------
# Exceptions (data.exceptions): {image, path, ticket, expires, reason}. `image` is the
# repository without tag or digest; `path` is a glob where * stays within one directory.
# An exception stops applying on its `expires` date (UTC).

default exceptions := []

exceptions := data.exceptions

exception_fields := ["image", "path", "ticket", "expires", "reason"]

valid_exception(e) if {
	every k in exception_fields { is_string(e[k]) }
	regex.match(`^\d{4}-\d{2}-\d{2}$`, e.expires)
}

active_exceptions(path) := {e |
	some e in exceptions
	valid_exception(e)
	e.image == image.repository
	glob.match(e.path, ["/"], path)
	time.now_ns() < time.parse_ns("2006-01-02", e.expires)
}

excepted(path) if count(active_exceptions(path)) > 0

# ---------------------------------------------------------------------------
# Configuration checks. A missing, misspelled or mistyped key would otherwise silently
# protect nothing.

config_keys := {"require_layered", "forbidden_packages", "protected_packages", "protected_files", "sealed_dirs", "appendable_dirs", "shadows"}

string_list_keys := ["forbidden_packages", "protected_packages", "protected_files", "sealed_dirs"]

# A separate rule, because `not is_object(data.integrity)` is undefined, not true, when the
# key is absent.
has_config if is_object(data.integrity)

config_errors contains "data.integrity is missing or not a map" if not has_config

config_errors contains sprintf("unknown key %s", [k]) if {
	some k, _ in cfg
	not k in config_keys
}

config_errors contains sprintf("%s must be a list of strings", [k]) if {
	some k in string_list_keys
	v := cfg[k]
	not string_list(v)
}

config_errors contains "require_layered must be true or false" if {
	v := cfg.require_layered
	not is_boolean(v)
}

config_errors contains "appendable_dirs must be a list of {dir, allow} entries" if {
	v := cfg.appendable_dirs
	not valid_appendable(v)
}

config_errors contains "shadows must map each directory to a list of directories" if {
	v := cfg.shadows
	not valid_shadows(v)
}

config_errors contains "nothing is protected" if {
	has_config
	every k in protection_keys { count(object.get(cfg, k, [])) == 0 }
}

protection_keys := ["protected_packages", "protected_files", "sealed_dirs", "appendable_dirs", "forbidden_packages"]

string_list(v) if {
	is_array(v)
	every x in v { is_string(x) }
}

valid_appendable(v) if {
	is_array(v)
	every a in v {
		is_string(a.dir)
		is_string(a.allow)
	}
}

valid_shadows(v) if {
	is_object(v)
	every _, targets in v { string_list(targets) }
}

# ---------------------------------------------------------------------------
# Results

deny contains {"msg": sprintf("invalid configuration: %s", [e])} if some e in config_errors

deny contains {"msg": message(v), "details": v} if {
	some v in findings
	not excepted(v.path)
}

warn contains {"msg": sprintf("allowed by exception %s until %s: %s", [e.ticket, e.expires, message(v)]), "details": v} if {
	some v in findings
	some e in active_exceptions(v.path)
}

deny contains {"msg": sprintf("%s; require_layered is set", [not_layered_msg])} if {
	not layered
	require_layered
}

warn contains {"msg": sprintf("%s; 'touched' checks are skipped, content checks still apply", [not_layered_msg])} if {
	not layered
	not require_layered
}

warn contains {"msg": sprintf("protected package %s is not installed in the base image", [name])} if {
	some name in cfg.protected_packages
	not base.packages[name]
}

warn contains {"msg": sprintf("ignoring malformed exception %v: needs %s, with expires quoted as \"YYYY-MM-DD\"", [e, concat(", ", exception_fields)])} if {
	some e in exceptions
	not valid_exception(e)
}

warn contains {"msg": sprintf("exception %s for %s expired on %s", [e.ticket, e.path, e.expires])} if {
	some e in exceptions
	valid_exception(e)
	e.image == image.repository
	time.now_ns() >= time.parse_ns("2006-01-02", e.expires)
}

# ---------------------------------------------------------------------------
# Helpers

finding(path, kind, layer, detail) := {"path": path, "kind": kind, "layer": layer, "detail": detail}

message(v) := sprintf("%s %s: %s%s", [v.kind, v.path, v.detail, layer_note(v.layer)])

layer_note(layer) := "" if {
	layer == ""
} else := sprintf(" (base layer %s)", [short(layer)]) if {
	layer in base_layers
} else := sprintf(" (layer %s)", [short(layer)])

short(digest) := substring(digest, 0, 19)

dir_prefix(d) := d if endswith(d, "/")

dir_prefix(d) := concat("", [d, "/"]) if not endswith(d, "/")

basename(p) := parts[count(parts) - 1] if parts := split(p, "/")

# "/etc/systemd/system/x.conf" -> {"/etc", "/etc/systemd", "/etc/systemd/system"}
ancestors(p) := {concat("/", array.slice(parts, 0, k)) |
	parts := split(p, "/")
	some k in numbers.range(2, count(parts))
	k < count(parts)
}

# "worker@one.service" -> "worker@.service"; other unit names are returned unchanged.
template_of(name) := name if not contains(name, "@")

template_of(name) := concat("", [substring(name, 0, indexof(name, "@") + 1), ".", type]) if {
	contains(name, "@")
	parts := split(name, ".")
	type := parts[count(parts) - 1]
}
