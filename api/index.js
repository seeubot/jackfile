// api/index.js
const { ContentProtectionAPI } = require('../src');

module.exports = async (req, res) => {
  // CORS headers
  res.setHeader('Access-Control-Allow-Credentials', true);
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,POST');
  res.setHeader(
    'Access-Control-Allow-Headers',
    'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version, Authorization'
  );

  // Handle OPTIONS request (preflight)
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  // Validate API key
  const apiKey = req.headers.authorization?.split(' ')[1];
  if (!apiKey) {
    return res.status(401).json({ error: 'Unauthorized', message: 'API key is required' });
  }
  
  // Initialize the protection API
  const protectionAPI = new ContentProtectionAPI({
    apiKey,
    serviceName: req.body.serviceName || 'default',
    sensitivityLevel: req.body.sensitivityLevel || 'medium',
    blockingStrategy: req.body.blockingStrategy || 'immediate',
    notificationEndpoint: req.body.notificationEndpoint,
    loggingLevel: req.body.loggingLevel || 'info'
  });

  try {
    // Route to the appropriate handler based on the endpoint
    const endpoint = req.query.endpoint || 'status';
    
    switch (endpoint) {
      case 'initialize':
        if (req.method !== 'POST') {
          return res.status(405).json({ error: 'Method not allowed' });
        }
        
        const initResult = await protectionAPI.initialize(req.body.sessionInfo || {});
        return res.status(200).json(initResult);
      
      case 'check':
        const sessionId = req.query.sessionId || req.body.sessionId;
        if (!sessionId) {
          return res.status(400).json({ error: 'Session ID is required' });
        }
        
        const securityStatus = await protectionAPI.checkSecurityStatus(sessionId);
        return res.status(200).json(securityStatus);
      
      case 'terminate':
        if (req.method !== 'POST') {
          return res.status(405).json({ error: 'Method not allowed' });
        }
        
        const terminateSessionId = req.body.sessionId;
        const reason = req.body.reason || 'Manual termination';
        
        if (!terminateSessionId) {
          return res.status(400).json({ error: 'Session ID is required' });
        }
        
        const terminateResult = protectionAPI.terminateStream(terminateSessionId, reason);
        return res.status(200).json(terminateResult);
      
      case 'cleanup':
        if (req.method !== 'POST') {
          return res.status(405).json({ error: 'Method not allowed' });
        }
        
        const cleanupSessionId = req.body.sessionId;
        if (!cleanupSessionId) {
          return res.status(400).json({ error: 'Session ID is required' });
        }
        
        protectionAPI.cleanup(cleanupSessionId);
        return res.status(200).json({ status: 'success', message: 'Session cleaned up' });
      
      default:
        return res.status(200).json({ 
          status: 'running',
          version: '1.0.0',
          timestamp: new Date().toISOString()
        });
    }
  } catch (error) {
    console.error('API Error:', error);
    return res.status(500).json({ 
      error: 'Internal server error', 
      message: error.message 
    });
  }
};
