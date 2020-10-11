import java.io.*;
import java.net.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;


class SocketServer extends Thread {
	
	Socket s;
	ServerSocket ss;
	int port;
	private static List<Message> messages = new ArrayList<>();
	private static List<String> recipients = new ArrayList<>();
	static List<Message> inbox = new ArrayList<>();
	private static String recipient;

	
	public SocketServer(int port) throws IOException {
		
		System.out.println("Listening for connections.." + "\n");
		
		this.port = port;
		
	}
	
	public void run() {
		
		try {
		
		ss = new ServerSocket(port);
		
		while(true) {
			
			s = ss.accept();
			
			System.out.println(s.getInetAddress() + " has connected\n");
			
			DataInputStream dis = new DataInputStream(s.getInputStream());
			
			DataOutputStream dos = new DataOutputStream(s.getOutputStream());
			
			String userId = dis.readUTF();
			
			inbox = checkInbox(userId); //Filters through inbox list to find appropriate messages for connected user
			
			try {
					
				dos.writeInt(inbox.size());
				
				if (inbox.size() > 0) {
					
					ObjectOutputStream inboxList = new ObjectOutputStream(s.getOutputStream());
					
					inboxList.writeObject(inbox);
					
					inbox.clear();
					
					inboxList.close();
					
				}
				
				String in = dis.readUTF();
				
				while(!in.equals("N")) {
					
					recipient = dis.readUTF();
					
					ObjectInputStream objectInputStream = new ObjectInputStream(s.getInputStream());
					
					if(!objectInputStream.equals(null)) {
						
						recipients.add(generateUseridHash(recipient));
					
						Message msg = (Message) objectInputStream.readObject();
						
						messages.add(msg);
						
					}
					
					in = dis.readUTF();
					
				}
						
				}catch(Exception e) { 
					
					System.out.println("Client Disconnectd");
					s.close();					
				}
			}
		 }catch (IOException e) {
			
			 e.printStackTrace();
			 
		 }
	}
	
	
	private static List<Message> checkInbox(String userId) {
		
		List<Integer> temp = new ArrayList<>();
		int tempi;
		
		//Collect inbox
		for(int i=0;i<recipients.size();i++) {
		
			if(userId.equals(recipients.get(i))){
					
				temp.add(i);
				inbox.add(messages.get(i));
			
			}
		
		}
		
		//Delete references
		for(int i=0;i<inbox.size();i++){
			
			tempi = temp.get(i);
		
			messages.remove(tempi - i); //-i as removing an item from a list causes an index shift
			
			recipients.remove(tempi - i);
			
		}
		
		return inbox;
		
	}
	
    
	public static String generateUseridHash(String userid) throws NoSuchAlgorithmException, UnsupportedEncodingException {
		
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		
		byte[] idBytes = userid.getBytes("UTF-8");
		
		byte[] output = md.digest(idBytes);
		
		return new String(output);
	}
}



class Server {
	
    public static void main(String [] args) {

		int port = Integer.parseInt(args[0]);
		
		try {
		
			SocketServer ss = new SocketServer(port);
			
			ss.run();
		
		} catch (IOException e) {
		
			e.printStackTrace();
		
		}
	}   
}



