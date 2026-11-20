FROM node@sha256:bd26af08779f746650d95a2e4d653b0fd3c8030c44284b6b98d701c9b5eb66b9
WORKDIR /suite
COPY --chmod=0444 observe.cjs owned.cjs cases.json seed.sql suite.json ./
WORKDIR /suite/calibration
COPY --chmod=0444 calibration/package.json ./package.json
WORKDIR /suite
USER 65534:65534
ENTRYPOINT ["node", "/suite/observe.cjs"]
