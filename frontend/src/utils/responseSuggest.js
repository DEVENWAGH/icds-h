function assetLabel(attack) {
  if (attack?.asset_name && attack?.asset_code) {
    return `${attack.asset_name} (${attack.asset_code})`
  }
  const line = attack?.impact_line || ''
  const match = line.match(/→\s*([^→]+?)\s*→/)
  if (match) return match[1].trim()
  if (attack?.dest_ip) return attack.dest_ip
  return 'the affected hospital system'
}

function contextText(attack) {
  return `${attack?.description || ''} ${attack?.suspicion_reason || ''} ${attack?.impact_line || ''} ${attack?.detail || ''}`.toLowerCase()
}

function pack(headline, steps) {
  return { headline, steps }
}

export function suggestResponse(attack) {
  const type = attack?.attack_type
  if (!type || type === 'Normal') return null

  const text = contextText(attack)
  const asset = assetLabel(attack)
  const source = attack?.source_ip && attack.source_ip !== 'N/A' ? attack.source_ip : null

  if (type === 'Insider Threat') {
    if (text.includes('not allowed') || text.includes('cannot update') || text.includes('denied')) {
      return pack('Keep the chart blocked and disable that login', [
        'Leave the denied request blocked. Do not grant EMR access.',
        'Disable the staff account until a hospital admin reviews it.',
        `Watch further attempts on ${asset}.`,
      ])
    }
    if (text.includes('outside')) {
      return pack('Limit this account to its own department', [
        'Stop further chart opens outside the staff member’s department.',
        'Ask the department head to confirm the access was needed.',
        `Keep ${asset} under review until that check is done.`,
      ])
    }
    if (text.includes('records in') || text.includes('bulk')) {
      return pack('Freeze the account and review the charts opened', [
        'Suspend the login that opened many records in a short time.',
        'List the patient charts opened in the last two minutes.',
        'Notify hospital admin before restoring access.',
      ])
    }
    return pack('Lock the account and limit record access', [
      'Disable the staff login until a supervisor reviews it.',
      'Restrict the account to its own department and systems.',
      `Audit new activity on ${asset}.`,
    ])
  }

  if (type === 'Password Attack' || type === 'Brute Force') {
    return pack('Lock the account and block the source on AD', [
      'Lock the targeted staff account on AD Auth Server (A006).',
      'Force a password reset before the next successful login.',
      source ? `Block ${source} at the auth server.` : 'Block the source address at the auth server.',
    ])
  }

  if (type === 'Ransomware') {
    return pack(`Isolate ${asset} and restore from backup`, [
      `Disconnect ${asset} from the hospital network.`,
      'Restore patient records from the last clean backup.',
      'Patch the entry point before the system is put back online.',
    ])
  }

  if (type === 'Phishing') {
    return pack('Block the lure and reset any account that opened it', [
      'Block the fraudulent address at the mail gateway.',
      'Reset credentials for anyone who opened the message.',
      'Quarantine the workstation that clicked the link.',
    ])
  }

  if (type === 'SQL Injection' || type === 'Injection') {
    return pack(`Block the injection and protect ${asset}`, [
      'Drop the source at the firewall.',
      'Turn on the web application rule that strips injection payloads.',
      `Patch the database connector on ${asset}.`,
    ])
  }

  if (type === 'XSS') {
    return pack('Block the script and patch the web form', [
      'Block the session that sent the script.',
      'Strip script tags at the web application firewall.',
      `Patch the input form on ${asset}.`,
    ])
  }

  if (type === 'DDoS' || type === 'DoS') {
    return pack(`Rate-limit traffic aimed at ${asset}`, [
      source ? `Block ${source} at the edge.` : 'Block the flood sources at the edge.',
      `Keep ${asset} reachable for clinical traffic only.`,
      'Hold the block until the flood stops.',
    ])
  }

  if (type === 'Scanning' || type === 'Port Scan') {
    return pack('Block the scanner and watch the probed ports', [
      source ? `Block ${source} at the firewall.` : 'Block the scanner address at the firewall.',
      'Drop further probe packets aimed at hospital systems.',
      `Raise monitoring on ${asset}.`,
    ])
  }

  if (type === 'MITM') {
    return pack('Isolate the rogue device on the hospital LAN', [
      'Remove the spoofing machine from the network.',
      'Block the rogue address and DNS redirect.',
      'Require certificate checks on the affected switch.',
    ])
  }

  if (type === 'Backdoor') {
    return pack(`Isolate ${asset} and reimage it`, [
      `Cut ${asset} off from command-and-control traffic.`,
      'Rebuild the host from a clean image.',
      'Patch the persistence path before it returns to service.',
    ])
  }

  if (type === 'Anomaly/Zero-Day' || type === 'Anomaly (Zero-Day)') {
    return pack(`Quarantine ${asset} until the pattern is identified`, [
      `Move ${asset} to a containment network.`,
      source ? `Block outbound traffic from ${source}.` : 'Block the unusual outbound traffic.',
      'Capture the process list before anyone changes the host.',
    ])
  }

  return pack(`Contain ${asset} and review the event`, [
    `Isolate ${asset} if clinical work can continue without it.`,
    source ? `Block ${source} until an analyst confirms the event.` : 'Block the source until an analyst confirms the event.',
    'Record what was accessed before closing the incident.',
  ])
}
