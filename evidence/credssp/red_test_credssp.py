"""Red evidence for the CredSSP layer.

Every mutation breaks one rule that the spec states explicitly. The suite must
fail for each one; a mutation that stays green means the corresponding test is
decoration, not a check.

Sources are restored byte-for-byte (sha256 verified) after every mutation, and
the build is re-verified green at the end so a crash mid-run cannot leave a
mutated tree behind.
"""
import hashlib
import io
import os
import shutil
import subprocess
import sys

sys.stdout.reconfigure(encoding='utf-8', errors='replace')

ROOT = r'F:\rtsc'
BUILD_BAT = os.path.join(ROOT, '.tmp', 'build_tls.bat')
TARGETS = {
    'credssp': (os.path.join(ROOT, 'src', 'credssp', 'credssp.cpp'),
                os.path.join(ROOT, 'build', 'verify', 'rtsc_credssp_sm_tests.exe')),
    'ntlm': (os.path.join(ROOT, 'src', 'credssp', 'ntlm.cpp'),
             os.path.join(ROOT, 'build', 'verify', 'rtsc_ntlm_tests.exe')),
    'tsreq': (os.path.join(ROOT, 'src', 'credssp', 'ts_request.cpp'),
              os.path.join(ROOT, 'build', 'verify', 'rtsc_credssp_tests.exe')),
}

# (target, name, description, old, new)
MUTATIONS = [
    ('credssp', 'C1_drop_magic_nul',
     '5.4.1: hash the magic without its NUL terminator',
     'const size_t magic_len = std::strlen(magic) + 1;',
     'const size_t magic_len = std::strlen(magic);'),

    ('credssp', 'C2_wrong_magic_order',
     '5.4.1: hash nonce before the magic instead of magic||nonce||key',
     '''    Bytes input(magic, magic + magic_len);
    input.insert(input.end(), nonce.begin(), nonce.end());
    input.insert(input.end(), key.begin(), key.end());''',
     '''    Bytes input(nonce.begin(), nonce.end());
    input.insert(input.end(), magic, magic + magic_len);
    input.insert(input.end(), key.begin(), key.end());'''),

    ('credssp', 'C3_skip_server_echo_check',
     '5.4.5 step 10: accept any server echo (loses MITM protection)',
     '    if (plain != expected) {\n'
     '        return Fail(Status::kMalformed, "server echo mismatch");\n'
     '    }',
     '    if (false) {\n'
     '        return Fail(Status::kMalformed, "server echo mismatch");\n'
     '    }'),

    ('credssp', 'C4_no_error_code_check',
     '5.3: process tokens even when the server reported an errorCode',
     '    if (req.has_error_code) {',
     '    if (false && req.has_error_code) {'),

    ('credssp', 'C5_nonce_on_old_versions',
     '5.1: send clientNonce for versions below 5',
     '    if (version_ >= kFirstHashVersion) req.client_nonce = nonce_;',
     '    req.client_nonce = nonce_;'),

    ('credssp', 'C6_raw_key_for_v5',
     '5.4.1: send the raw public key instead of the binding hash',
     '        plain = ClientToServerBindingHash(server_public_key_, nonce_);',
     '        plain = server_public_key_;'),

    ('credssp', 'C7_no_mic',
     '6.5: omit the MIC even when the challenge carries a timestamp',
     '    if (have_timestamp) {\n'
     '        const auto mic = ComputeMic(',
     '    if (false) {\n'
     '        const auto mic = ComputeMic('),

    ('credssp', 'C8_fresh_rc4_per_message',
     '5.4.3: restart the RC4 stream for each sealed message',
     '    sealed.ciphertext = send_rc4_.Apply(plaintext);',
     '    send_rc4_.Init(sealing_key_.data(), sealing_key_.size());\n'
     '    sealed.ciphertext = send_rc4_.Apply(plaintext);'),

    ('ntlm', 'N1_av_order_reversed',
     '7.5: build temp without the trailing Z(4)',
     '''    temp.insert(temp.end(), in.target_info.begin(), in.target_info.end());
    temp.insert(temp.end(), 4, 0);''',
     '    temp.insert(temp.end(), in.target_info.begin(), in.target_info.end());'),

    ('ntlm', 'N2_session_base_key_from_response',
     '6.5: derive SessionBaseKey from the whole response instead of NTProofStr',
     '''    const auto sbk = crypto::HmacMd5(response_key.data(), response_key.size(),
                                     out.nt_proof_str.data(),
                                     out.nt_proof_str.size());''',
     '''    const auto sbk = crypto::HmacMd5(response_key.data(), response_key.size(),
                                     out.nt_response.data(),
                                     out.nt_response.size());'''),

    ('ntlm', 'N3_no_lm_zeroing',
     '6.5: send a real LMv2 response even when a timestamp is present',
     '    if (in.suppress_lm_response) {\n'
     '        out.lm_response.assign(24, 0);\n'
     '    } else {',
     '    if (false) {\n'
     '        out.lm_response.assign(24, 0);\n'
     '    } else {'),

    ('ntlm', 'N4_mic_not_zeroed',
     '6.5: hash the MIC field as-is instead of zeroing it first',
     '        std::fill(auth.begin() + 72, auth.begin() + 88, static_cast<uint8_t>(0));',
     '        // mutation: MIC left as-is'),

    ('ntlm', 'N5_authenticate_header_64',
     '6.3: use a 64-byte AUTHENTICATE header instead of 88',
     'constexpr size_t kAuthenticateHeaderSize = 88;',
     'constexpr size_t kAuthenticateHeaderSize = 64;'),

    ('tsreq', 'T1_no_ascending_tag_check',
     '5.7: accept context tags in any order',
     '        if (number <= last_tag && !(last_tag == 0 && number == 0 && !have_version)) {',
     '        if (false) {'),

    ('tsreq', 'T2_reject_noncanonical_error',
     '5.7: reject the server non-canonical errorCode (raw 4-byte unsigned)',
     '    if (length == 5) {',
     '    if (length == 5 && false) {'),

    ('tsreq', 'T3_nonce_length_unchecked',
     '5.1: accept a clientNonce of any length',
     '    } else if (client_nonce.size() != kNonceSize) {',
     '    } else if (false) {'),
]


def sha(p):
    return hashlib.sha256(open(p, 'rb').read()).hexdigest()


def build():
    r = subprocess.run(['cmd', '/c', BUILD_BAT], capture_output=True, text=True,
                       encoding='utf-8', errors='replace')
    return r.returncode, (r.stdout or '') + (r.stderr or '')


def run(exe):
    r = subprocess.run([exe], capture_output=True, text=True,
                       encoding='utf-8', errors='replace')
    lines = [l for l in (r.stdout or '').splitlines() if l.strip()]
    return r.returncode, lines[-1] if lines else ''


def main():
    originals = {}
    shas = {}
    for key, (src, _exe) in TARGETS.items():
        originals[key] = io.open(src, encoding='utf-8', newline='').read()
        shas[key] = sha(src)

    rc, msg = build()
    if rc != 0:
        print('BASELINE BUILD FAILED')
        print(msg[-800:])
        return 2
    for key, (_src, exe) in TARGETS.items():
        rc, last = run(exe)
        print('baseline %-8s exit=%d  %s' % (key, rc, last))
        if rc != 0:
            print('baseline not green; refusing to mutate')
            return 2

    results = []
    try:
        for target, name, desc, old, new in MUTATIONS:
            src = TARGETS[target][0]
            text = originals[target]
            if old not in text:
                results.append((name, desc, 'ANCHOR-MISSING', ''))
                print('%-30s ANCHOR MISSING' % name)
                continue
            io.open(src, 'w', encoding='utf-8', newline='').write(
                text.replace(old, new, 1))
            brc, bmsg = build()
            if brc != 0:
                err = [l for l in bmsg.splitlines() if 'error' in l.lower()]
                results.append((name, desc, 'BUILD-FAIL', err[0][:70] if err else ''))
                print('%-30s BUILD-FAIL' % name)
            else:
                rrc, rlast = run(TARGETS[target][1])
                verdict = 'CAUGHT' if rrc != 0 else 'MISSED'
                results.append((name, desc, verdict, rlast))
                print('%-30s %-8s %s' % (name, verdict, rlast[:56]))
            io.open(src, 'w', encoding='utf-8', newline='').write(originals[target])
    finally:
        for key, (src, _exe) in TARGETS.items():
            io.open(src, 'w', encoding='utf-8', newline='').write(originals[key])

    print()
    ok = True
    for key, (src, _exe) in TARGETS.items():
        same = sha(src) == shas[key]
        print('restored %-8s %s' % (key, 'IDENTICAL' if same else 'MISMATCH'))
        ok = ok and same

    rc, msg = build()
    green = True
    for key, (_src, exe) in TARGETS.items():
        rrc, last = run(exe)
        if rrc != 0:
            green = False
        print('rebuilt  %-8s exit=%d  %s' % (key, rrc, last))

    missed = [r for r in results if r[2] == 'MISSED']
    missing = [r for r in results if r[2] == 'ANCHOR-MISSING']
    caught = len([r for r in results if r[2] == 'CAUGHT'])
    print()
    print('mutations=%d  caught=%d  build-fail=%d  missed=%d  anchor-missing=%d'
          % (len(results), caught,
             len([r for r in results if r[2] == 'BUILD-FAIL']),
             len(missed), len(missing)))
    ok = ok and green and rc == 0 and not missed and not missing
    print('RESULT=%s' % ('PASS' if ok else 'FAIL'))
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
