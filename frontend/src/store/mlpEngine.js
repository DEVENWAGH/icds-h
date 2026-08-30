import api from '../utils/api'

export async function runMLPInference(attack_log_id) {
  if (
    attack_log_id === undefined ||
    attack_log_id === null ||
    attack_log_id === ''
  ) {
    throw new Error('No attack_log_id provided for prediction.')
  }

  const { data } = await api.post(
    `/predict/?attack_log_id=${attack_log_id}`
  )

  const predictionLabel = data?.prediction_label ?? 'Unknown'
  const riskScore = Number(data?.risk_score ?? 0)
  const confidence = Number(data?.confidence ?? 0)

  const isAttack = predictionLabel !== 'Normal'

  return {
    prediction_label: predictionLabel,
    prediction_type: isAttack ? 'ATTACK' : 'NORMAL',
    attack_type: isAttack ? predictionLabel : null,

    risk_score: riskScore,
    confidence,

    pred_probability: confidence / 100,

    status:
      riskScore > 70
        ? 'CRITICAL'
        : riskScore > 40
          ? 'WARNING'
          : 'STABLE',

    risk_band: {
      label:
        riskScore > 70
          ? 'CRITICAL'
          : riskScore > 40
            ? 'HIGH'
            : 'LOW',
      color:
        riskScore > 70
          ? '#ff2d55'
          : riskScore > 40
            ? '#ffd60a'
            : '#00ff88',
    },

    confidence_band: {
      label:
        confidence >= 90
          ? 'Very High'
          : confidence >= 80
            ? 'High'
            : 'Moderate',
      description: 'Based on model probability distribution',
    },

    // This is MLP inference. SHAP is handled separately by XAI.
    method: 'MLP',

    explanation_text: null,

    model_version: data?.model_version ?? 'N/A',
    dataset: data?.dataset ?? 'N/A',

    predicted_at: new Date().toISOString(),
    attack_log_id,
  }
}

// Current-session prediction history.
// This is NOT persistent backend history.
const _history = []

export function addToHistory(result) {
  if (!result) return

  _history.unshift({
    id: `${result.attack_log_id}-${Date.now()}`,
    time: new Date().toLocaleTimeString('en-GB', {
      hour12: false,
    }),
    attack_type: result.attack_type || 'Normal',
    prediction_type: result.prediction_type,
    confidence: result.confidence,
    risk_score: result.risk_score,
    dataset: result.dataset,
    attack_log_id: result.attack_log_id,
  })

  if (_history.length > 30) {
    _history.pop()
  }
}

export function getPredictionHistory() {
  return [..._history]
}