package br.senai.jandira.IPAnalyzerApp.java;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.net.InetAddress;
import java.net.UnknownHostException;

public class IPAnalyzerApp extends JFrame implements ActionListener {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	private JTextField ipMaskTextField;
	private JTextArea resultTextArea;
	private JButton analyzeButton;

	public IPAnalyzerApp() {
		setTitle("Analisador de IP");
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setSize(400, 300);
		setLayout(new FlowLayout());

		JLabel ipMaskLabel = new JLabel("Digite o IP/Máscara (ex: 192.168.0.0/24):");
		ipMaskTextField = new JTextField(20);
		analyzeButton = new JButton("Analisar");
		analyzeButton.addActionListener(this);
		resultTextArea = new JTextArea(10, 30);
		resultTextArea.setEditable(false);

		add(ipMaskLabel);
		add(ipMaskTextField);
		add(analyzeButton);
		add(new JScrollPane(resultTextArea));

		setVisible(true);
	}

	public static void main(String[] args) {
		SwingUtilities.invokeLater(IPAnalyzerApp::new);
	}

	@Override
	public void actionPerformed(ActionEvent e) {
		if (e.getSource() == analyzeButton) {
			String ipMask = ipMaskTextField.getText();
			analyzeIP(ipMask);
		}
	}

	private void analyzeIP(String ipMask) {
		try {
			String[] parts = ipMask.split("/");
			String ipAddress = parts[0];
			int cidr = Integer.parseInt(parts[1]);

			InetAddress inetAddress = InetAddress.getByName(ipAddress);
			byte[] ipBytes = inetAddress.getAddress();

			String ipClass = determineIPClass(ipBytes[0] & 0xFF);
			String decimalMask = calculateDecimalMask(cidr);
			String binaryMask = calculateBinaryMask(cidr);
			long availableIPs = calculateAvailableIPs(cidr);

			StringBuilder result = new StringBuilder();
			result.append("IP Digitado: ").append(ipMask).append("\n");
			result.append("Classe do IP: ").append(ipClass).append("\n");
			result.append("Máscara Decimal: ").append(decimalMask).append("\n");
			result.append("Máscara Binária: ").append(binaryMask).append("\n");
			result.append("IPs Disponíveis: ").append(availableIPs).append("\n\n");
			result.append("--- Sugestões para Subredes ---\n");
			result.append("Ao criar subredes, a máscara (CIDR) se torna maior (ex: /25, /26).\n");
			result.append("Um CIDR maior significa menos IPs disponíveis por sub-rede, mas mais sub-redes.\n");
			result.append("Por exemplo, ao dividir a rede /24 em subredes /25:\n");
			result.append("  - A nova máscara decimal seria 255.255.255.128.\n");
			result.append("  - A nova máscara binária teria um bit '1' adicional à direita.\n");
			result.append(
					"  - Cada sub-rede teria 2^(32-25) - 2 = 126 IPs disponíveis (lembrando do endereço de rede e broadcast).\n");
			result.append("  - Seriam criadas 2^(25-24) = 2 sub-redes.\n");
			result.append("É importante planejar o número de subredes e hosts por sub-rede necessários para sua rede.");

			resultTextArea.setText(result.toString());

		} catch (ArrayIndexOutOfBoundsException | NumberFormatException e) {
			resultTextArea.setText("Formato de IP/Máscara inválido. Use o formato: 192.168.0.0/24");
		} catch (UnknownHostException e) {
			resultTextArea.setText("Endereço IP inválido.");
		}
	}

	private String determineIPClass(int firstOctet) {
		if (firstOctet >= 1 && firstOctet <= 126) {
			return "A";
		} else if (firstOctet >= 128 && firstOctet <= 191) {
			return "B";
		} else if (firstOctet >= 192 && firstOctet <= 223) {
			return "C";
		} else if (firstOctet >= 224 && firstOctet <= 239) {
			return "D (Multicast)";
		} else if (firstOctet >= 240 && firstOctet <= 254) {
			return "E (Reservado)";
		} else {
			return "Desconhecida";
		}
	}

	private String calculateDecimalMask(int cidr) {
		if (cidr < 0 || cidr > 32) {
			return "Máscara CIDR inválida";
		}
		int mask = 0xFFFFFFFF << (32 - cidr);
		return String.format("%d.%d.%d.%d", (mask >>> 24) & 0xFF, (mask >>> 16) & 0xFF, (mask >>> 8) & 0xFF,
				mask & 0xFF);
	}

	private String calculateBinaryMask(int cidr) {
		if (cidr < 0 || cidr > 32) {
			return "Máscara CIDR inválida";
		}
		StringBuilder binaryMask = new StringBuilder();
		for (int i = 0; i < 32; i++) {
			if (i < cidr) {
				binaryMask.append("1");
			} else {
				binaryMask.append("0");
			}
			if ((i + 1) % 8 == 0 && i < 31) {
				binaryMask.append(".");
			}
		}
		return binaryMask.toString();
	}

	private long calculateAvailableIPs(int cidr) {
		if (cidr < 0 || cidr > 32) {
			return 0;
		}
		long totalIPs = (long) Math.pow(2, (32 - cidr));
		// Subtrai o endereço de rede e o endereço de broadcast
		return totalIPs > 2 ? totalIPs - 2 : 0;
	}
}