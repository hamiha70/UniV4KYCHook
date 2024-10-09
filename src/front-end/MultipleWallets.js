import React, { useState } from 'react';
import { useConnect, useAccount, useDisconnect } from 'wagmi';
import { InjectedConnector } from 'wagmi/connectors/injected';

function MultipleWallets() {
  const [currentRole, setCurrentRole] = useState(null);
  const { connect, connectors } = useConnect();
  const { address, isConnected } = useAccount();
  const { disconnect } = useDisconnect();

  const roles = ['swapper', 'maliciousSwapper', 'PolicyOwner', 'HookOwner', 'TokenPolicyOwner'];

  return (
    <div>
      {roles.map((role) => (
        <button key={role} onClick={() => setCurrentRole(role)}>
          Connect as {role}
        </button>
      ))}
      {isConnected ? (
        <div>
          <p>Connected as {currentRole}: {address}</p>
          <button onClick={() => disconnect()}>Disconnect</button>
        </div>
      ) : (
        connectors.map((connector) => (
          <button key={connector.id} onClick={() => connect({ connector })}>
            Connect with {connector.name}
          </button>
        ))
      )}
    </div>
  );
}

export default MultipleWallets;
