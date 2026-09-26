export const HOSPITAL_STAFF = [
  'hospital_admin',
  'doctor',
  'nurse',
  'lab_technician',
  'receptionist',
]

export const PATIENT_ROLES = [
  'admin',
  'clinical',
  'hospital_admin',
  'doctor',
  'nurse',
  'lab_technician',
  'receptionist',
]

export const ACCESS_LOG_ROLES = [...PATIENT_ROLES, 'analyst']

export const STAFF_ADMIN_ROLES = ['admin', 'hospital_admin']

export const HOSPITAL_VIEW_ROLES = [...ACCESS_LOG_ROLES]

export function homeForRole(role) {
  if (HOSPITAL_STAFF.includes(role)) return '/app/hospital'
  if (role === 'clinical') return '/app/dashboard'
  return '/app/command'
}

const RISK_WORD = {
  CRITICAL: 'Critical',
  HIGH: 'High',
  MEDIUM: 'Medium',
  LOW: 'Low',
}

export function impactLine(incident) {
  if (!incident) return ''
  if (incident.impact_line) return incident.impact_line
  if (!incident.attack_type || incident.attack_type === 'Normal') {
    return incident.attack_type || ''
  }
  const name = incident.asset_name || 'Hospital Asset'
  const code = incident.asset_code || 'A001'
  const word = RISK_WORD[String(incident.severity || 'HIGH').toUpperCase()] || 'High'
  return `${incident.attack_type} detected → ${name} (${code}) → ${word} Risk`
}
