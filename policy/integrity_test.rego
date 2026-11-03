package main_test

import data.main

cfg := {
	"protected_packages": ["openssh-server"],
	"protected_files": [
		"/opt/agent/bin/agent",
		"/usr/lib/systemd/system/agent.service",
		"/usr/lib/sysctl.d/99-hardening.conf",
		"/etc/ld.so.preload",
	],
	"sealed_dirs": ["/etc/pam.d"],
	"appendable_dirs": [{"dir": "/etc/ssh/sshd_config.d/", "allow": `^[5-9][0-9]-[A-Za-z0-9_.-]+\.conf$`}],
	"shadows": {
		"/usr/lib/sysctl.d/": ["/etc/sysctl.d/"],
		"/usr/lib/systemd/system/": ["/etc/systemd/system/"],
		"/usr/bin/": ["/usr/local/bin/"],
	},
}

file(sha, layer) := {"type": "RegularFile", "mode": 644, "uid": 0, "gid": 0, "sha256": sha, "link": "", "layer": layer}

dir(layer) := {"type": "Directory", "mode": 20000000755, "uid": 0, "gid": 0, "sha256": "", "link": "", "layer": layer}

symlink(dest, layer) := {"type": "SymbolicLink", "mode": 1000000777, "uid": 0, "gid": 0, "sha256": "", "link": dest, "layer": layer}

base_files := {
	"/usr/bin/sshd": file("sshd", "L1"),
	"/etc/ssh/sshd_config.d": dir("L1"),
	"/etc/ssh/sshd_config.d/00-hardening.conf": file("hardening", "L2"),
	"/opt/agent/bin/agent": file("agent", "L2"),
	"/usr/lib/systemd/system/agent.service": file("unit", "L2"),
	"/etc/systemd/system/multi-user.target.wants/agent.service": symlink("/usr/lib/systemd/system/agent.service", "L2"),
	"/usr/lib/sysctl.d/99-hardening.conf": file("sysctl", "L2"),
	"/etc/pam.d": dir("L1"),
	"/etc/pam.d/sshd": file("pam", "L1"),
}

base := {
	"repository": "registry.example.com/base",
	"layers": ["L1", "L2"],
	"files": base_files,
	# /usr/share/ghost is an rpm %ghost entry: owned but never on disk.
	"packages": {"openssh-server": ["/usr/bin/sshd", "/etc/ssh/sshd_config.d", "/usr/share/ghost"]},
}

# A derived image: the base plus one added layer L3, with `changes` applied and `removed` deleted.
derived(changes, removed) := {"base": base, "image": {
	"repository": "registry.example.com/team/app",
	"layers": ["L1", "L2", "L3"],
	"files": object.union(object.remove(base_files, removed), changes),
	"packages": base.packages,
}}

squashed(changes) := {"base": base, "image": {
	"repository": "registry.example.com/team/app",
	"layers": ["S1"],
	"files": {p: object.union(f, {"layer": "S1"}) | some p, f in object.union(base_files, changes)},
	"packages": base.packages,
}}

found(results) := {[r.details.kind, r.details.path] | some r in results}

messages(results) := {r.msg | some r in results}

deny_for(inp) := results if {
	results := main.deny with input as inp with data.integrity as cfg
}

warn_for(inp) := results if {
	results := main.warn with input as inp with data.integrity as cfg
}

test_untouched_derived_image_passes if {
	inp := derived(
		{
			"/usr/share/app/index.html": file("app", "L3"),
			"/etc/ssh/sshd_config.d": dir("L3"), # adding a file rewrites the directory entry
			"/etc/ssh/sshd_config.d/60-app.conf": file("app-sshd", "L3"),
		},
		[],
	)
	count(deny_for(inp)) == 0
	count(warn_for(inp)) == 0
}

test_modified_protected_file if {
	found(deny_for(derived({"/opt/agent/bin/agent": file("evil", "L3")}, []))) == {["modified", "/opt/agent/bin/agent"]}
}

test_modified_reports_changed_fields if {
	inp := derived({"/etc/ssh/sshd_config.d/00-hardening.conf": object.union(file("hardening", "L3"), {"mode": 666})}, [])
	messages(deny_for(inp)) == {"modified /etc/ssh/sshd_config.d/00-hardening.conf: changed mode (layer L3)"}
}

test_deleted_package_file if {
	found(deny_for(derived({}, ["/usr/bin/sshd"]))) == {["deleted", "/usr/bin/sshd"]}
}

forbid := object.union(cfg, {"forbidden_packages": ["telnet", "telnet-server"]})

with_telnet := object.union(derived({}, []), {"image": {"packages": {"telnet": ["/usr/bin/telnet"]}}})

test_forbidden_package_installed if {
	denied := main.deny with input as with_telnet with data.integrity as forbid
	messages(denied) == {"forbidden telnet: package must not be installed"}
}

test_forbidden_package_fails_even_if_base_has_it if {
	inp := object.union(with_telnet, {"base": {"packages": {"telnet": ["/usr/bin/telnet"]}}})
	denied := main.deny with input as inp with data.integrity as forbid
	found(denied) == {["forbidden", "telnet"]}
}

test_forbidden_package_absent_passes if {
	denied := main.deny with input as derived({}, []) with data.integrity as forbid
	count(denied) == 0
}

test_forbidden_package_exception if {
	exceptions := [exception({"path": "telnet"})]
	denied := main.deny with input as with_telnet with data.integrity as forbid with data.exceptions as exceptions
	warned := main.warn with input as with_telnet with data.integrity as forbid with data.exceptions as exceptions
	count(denied) == 0
	messages(warned) == {"allowed by exception SEC-1 until 2099-01-01: forbidden telnet: package must not be installed"}
}

test_forbidden_path_added if {
	found(deny_for(derived({"/etc/ld.so.preload": file("preload", "L3")}, []))) == {["added", "/etc/ld.so.preload"]}
}

test_shadow_paths if {
	inp := derived(
		{
			"/etc/sysctl.d/99-hardening.conf": symlink("/dev/null", "L3"),
			"/usr/local/bin/sshd": file("fake-sshd", "L3"),
			"/etc/systemd/system/agent.service": symlink("/dev/null", "L3"),
		},
		[],
	)
	found(deny_for(inp)) == {
		["added", "/etc/sysctl.d/99-hardening.conf"],
		["added", "/usr/local/bin/sshd"],
		["added", "/etc/systemd/system/agent.service"],
	}
}

test_unit_dropins if {
	inp := derived(
		{
			"/etc/systemd/system/agent.service.d/override.conf": file("override", "L3"),
			"/usr/lib/systemd/system/agent.service.d/10-x.conf": file("override", "L3"),
		},
		[],
	)
	found(deny_for(inp)) == {
		["added", "/etc/systemd/system/agent.service.d/override.conf"],
		["added", "/usr/lib/systemd/system/agent.service.d/10-x.conf"],
	}
}

test_units_and_dropins_in_other_unit_dirs if {
	inp := derived(
		{
			"/usr/local/lib/systemd/system/agent.service": file("fake-unit", "L3"),
			"/etc/systemd/system.control/agent.service": symlink("/dev/null", "L3"),
			"/usr/local/lib/systemd/system/agent.service.d/override.conf": file("override", "L3"),
			"/etc/systemd/system.control/agent.service.d/override.conf": file("override", "L3"),
			"/etc/systemd/system.attached/agent.service.d/override.conf": file("override", "L3"),
		},
		[],
	)
	found(deny_for(inp)) == {
		["added", "/usr/local/lib/systemd/system/agent.service"],
		["added", "/etc/systemd/system.control/agent.service"],
		["added", "/usr/local/lib/systemd/system/agent.service.d/override.conf"],
		["added", "/etc/systemd/system.control/agent.service.d/override.conf"],
		["added", "/etc/systemd/system.attached/agent.service.d/override.conf"],
	}
}

test_dropins_for_every_service if {
	inp := derived({"/etc/systemd/system/service.d/10-app.conf": file("preload", "L3")}, [])
	found(deny_for(inp)) == {["added", "/etc/systemd/system/service.d/10-app.conf"]}
}

test_dropin_names if {
	main.dropin_names("agent.service") == {"agent.service.d", "service.d"}
	main.dropin_names("falcon-sensor-x.service") == {
		"falcon-sensor-x.service.d",
		"falcon-sensor-.service.d",
		"falcon-.service.d",
		"service.d",
	}
}

test_application_units_allowed if {
	inp := derived(
		{
			"/etc/systemd/system/app.service": file("app-unit", "L3"),
			"/etc/systemd/system/app.service.d/10-limits.conf": file("limits", "L3"),
			"/etc/systemd/system/multi-user.target.wants/app.service": symlink("/etc/systemd/system/app.service", "L3"),
		},
		[],
	)
	count(deny_for(inp)) == 0
}

test_disabling_protected_unit if {
	found(deny_for(derived({}, ["/etc/systemd/system/multi-user.target.wants/agent.service"]))) == {["deleted", "/etc/systemd/system/multi-user.target.wants/agent.service"]}
}

test_appendable_dir_names if {
	inp := derived(
		{
			"/etc/ssh/sshd_config.d/01-debug.conf": file("debug", "L3"),
			"/etc/ssh/sshd_config.d/60-app/nested.conf": file("nested", "L3"),
			"/etc/ssh/sshd_config.d/60-app.conf": file("ok", "L3"),
		},
		[],
	)
	found(deny_for(inp)) == {
		["added", "/etc/ssh/sshd_config.d/01-debug.conf"],
		["added", "/etc/ssh/sshd_config.d/60-app/nested.conf"],
	}
}

test_sealed_dir if {
	inp := derived(
		{
			"/etc/pam.d": object.union(dir("L3"), {"mode": 20000000777}),
			"/etc/pam.d/sshd": file("weakened", "L3"),
			"/etc/pam.d/evil": file("evil", "L3"),
		},
		[],
	)
	found(deny_for(inp)) == {
		["modified", "/etc/pam.d"],
		["modified", "/etc/pam.d/sshd"],
		["added", "/etc/pam.d/evil"],
	}
}

test_touched_in_added_layer if {
	found(deny_for(derived({"/usr/bin/sshd": file("sshd", "L3")}, []))) == {["touched", "/usr/bin/sshd"]}
}

test_squashed_image_skips_touched_but_checks_content if {
	inp := squashed({"/usr/bin/sshd": file("sshd", "S1"), "/opt/agent/bin/agent": file("evil", "S1")})
	found(deny_for(inp)) == {["modified", "/opt/agent/bin/agent"]}
	some msg in messages(warn_for(inp))
	startswith(msg, "base layers are not an unchanged prefix")
}

test_require_layered_fails_squashed_image if {
	strict := object.union(cfg, {"require_layered": true})
	inp := squashed({"/opt/agent/bin/agent": file("evil", "S1")})
	denied := main.deny with input as inp with data.integrity as strict
	warned := main.warn with input as inp with data.integrity as strict
	found(denied) == {["modified", "/opt/agent/bin/agent"]}
	some msg in messages(denied)
	startswith(msg, "base layers are not an unchanged prefix")
	count(warned) == 0
}

test_require_layered_passes_layered_image if {
	strict := object.union(cfg, {"require_layered": true})
	denied := main.deny with input as derived({}, []) with data.integrity as strict
	count(denied) == 0
}

exception(overrides) := object.union(
	{
		"image": "registry.example.com/team/app",
		"path": "/etc/ld.so.*",
		"ticket": "SEC-1",
		"expires": "2099-01-01",
		"reason": "test",
	},
	overrides,
)

preload := derived({"/etc/ld.so.preload": file("preload", "L3")}, [])

test_active_exception_downgrades_to_warning if {
	denied := deny_for(preload) with data.exceptions as [exception({})]
	warned := warn_for(preload) with data.exceptions as [exception({})]
	count(denied) == 0
	messages(warned) == {"allowed by exception SEC-1 until 2099-01-01: added /etc/ld.so.preload: not present in the base image (layer L3)"}
}

test_overlapping_exceptions if {
	exceptions := [exception({}), exception({"ticket": "SEC-2", "path": "/etc/ld.so.preload"})]
	denied := deny_for(preload) with data.exceptions as exceptions
	warned := warn_for(preload) with data.exceptions as exceptions
	count(denied) == 0
	count(warned) == 2
}

test_expired_exception if {
	exceptions := [exception({"expires": "2000-01-01"})]
	denied := deny_for(preload) with data.exceptions as exceptions
	warned := warn_for(preload) with data.exceptions as exceptions
	found(denied) == {["added", "/etc/ld.so.preload"]}
	messages(warned) == {"exception SEC-1 for /etc/ld.so.* expired on 2000-01-01"}
}

test_exception_for_other_image if {
	denied := deny_for(preload) with data.exceptions as [exception({"image": "registry.example.com/team/other"})]
	found(denied) == {["added", "/etc/ld.so.preload"]}
}

test_malformed_exception_is_ignored if {
	exceptions := [exception({"expires": "2099-01-01T00:00:00Z"})]
	denied := deny_for(preload) with data.exceptions as exceptions
	warned := warn_for(preload) with data.exceptions as exceptions
	found(denied) == {["added", "/etc/ld.so.preload"]}
	some msg in messages(warned)
	startswith(msg, "ignoring malformed exception")
}

test_missing_protected_package if {
	warned := main.warn with input as derived({}, []) with data.integrity as object.union(cfg, {"protected_packages": ["openssh-server", "nope"]})
	messages(warned) == {"protected package nope is not installed in the base image"}
}

# --- review findings -------------------------------------------------------

test_symlinked_sealed_dir if {
	inp := derived(
		{
			"/etc/systemd/system/agent.service.d": symlink("/opt/overrides", "L3"),
			"/opt/overrides/override.conf": file("override", "L3"),
		},
		[],
	)
	found(deny_for(inp)) == {["added", "/etc/systemd/system/agent.service.d"]}
}

test_symlinked_ancestor if {
	inp := derived({"/etc/systemd/system.control": symlink("/opt/control", "L3")}, [])
	found(deny_for(inp)) == {["added", "/etc/systemd/system.control"]}
}

test_base_symlink_unchanged_passes if {
	inp := {
		"base": object.union(base, {"files": {"/opt": symlink("var/opt", "L1")}}),
		"image": object.union(derived({}, [])["image"], {"files": {"/opt": symlink("var/opt", "L1")}}),
	}
	count(deny_for(inp)) == 0
}

test_missing_config_fails if {
	denied := main.deny with input as derived({}, []) with data.integrity as null
	messages(denied) == {"invalid configuration: data.integrity is missing or not a map"}
}

test_empty_config_fails if {
	denied := main.deny with input as derived({}, []) with data.integrity as {}
	messages(denied) == {"invalid configuration: nothing is protected; set protected_packages or protected_files"}
}

test_mistyped_config_fails if {
	bad := object.union(cfg, {"sealed_dirs": "/etc/pam.d", "protected_file": ["/x"], "require_layered": "yes"})
	denied := main.deny with input as derived({}, []) with data.integrity as bad
	messages(denied) == {
		"invalid configuration: sealed_dirs must be a list of strings",
		"invalid configuration: unknown key protected_file",
		"invalid configuration: require_layered must be true or false",
	}
}

template_files := object.union(base_files, {
	"/usr/lib/systemd/system/worker@.service": file("worker", "L2"),
	"/etc/systemd/system/multi-user.target.wants/worker@one.service": symlink("/usr/lib/systemd/system/worker@.service", "L2"),
})

template_cfg := object.union(cfg, {"protected_files": array.concat(cfg.protected_files, ["/usr/lib/systemd/system/worker@.service"])})

template_input(changes, removed) := {
	"base": object.union(base, {"files": template_files}),
	"image": object.union(derived({}, [])["image"], {"files": object.union(object.remove(template_files, removed), changes)}),
}

test_template_instance_overrides if {
	inp := template_input(
		{
			"/etc/systemd/system/worker@one.service": file("fake", "L3"),
			"/etc/systemd/system/worker@one.service.d/override.conf": file("override", "L3"),
		},
		[],
	)
	denied := main.deny with input as inp with data.integrity as template_cfg
	found(denied) == {
		["added", "/etc/systemd/system/worker@one.service"],
		["added", "/etc/systemd/system/worker@one.service.d/override.conf"],
	}
}

test_template_instance_disabled if {
	inp := template_input({}, ["/etc/systemd/system/multi-user.target.wants/worker@one.service"])
	denied := main.deny with input as inp with data.integrity as template_cfg
	found(denied) == {["deleted", "/etc/systemd/system/multi-user.target.wants/worker@one.service"]}
}
