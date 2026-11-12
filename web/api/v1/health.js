module.exports = (req, res) => {
  res.status(200).json({
    ok: true,
    service: 'env-checker-control-plane',
    domain: 'env.kishor.tech',
    engine: 'rust-simd-v1',
    timestamp: new Date().toISOString()
  });
};
