package cryptography;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.BitSet;
import java.nio.ByteBuffer;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 * @author lindelof
 * @since Nov 09, 2013
 */
public class EFS extends Utility{
	
	private static final byte DELIMITTER = 0;
	private static final int SALT_LEN = 16;
	private static final int AES_BLOCK_SIZE = 128;
	
	private static final int OFFSET_PASSWORD = 0;
	private static final int OFFSET_USERNAME = 128;
	private static final int OFFSET_LENGTH = 256;
	private static final int OFFSET_START_POS = 384;
	private static final int OFFSET_FEK = 512;
	private static final int OFFSET_IV = 640;
	
	private static final int META_INDEX = 0;
	private static final int META_MAC_INDEX = 1;
	
    
    public EFS(Editor e)
    {
        super(e);
    }

    @Override
    public void create(String file_name, String user_name, String password) throws Exception {
    	
    	//check legitimacy of username and password
    	if(user_name.length() > 128 || user_name.length() < 1)
    		throw new UnsupportedOperationException("username is not valid");
    	if(password.length() > 128 || password.length() < 1)
    		throw new UnsupportedOperationException("password is not valid");   	
    	
    	//meta data buffer, initialized with all 0's
    	byte[] toWrite = new byte[Config.BLOCK_SIZE];
    	int ptr;
    	
    	//------------------------------------------------
    	//1. write encrypted password first, r|h(password|r)
    	//------------------------------------------------
    	ptr = OFFSET_PASSWORD;
    	byte[] salt = (new SecureRandom()).generateSeed(SALT_LEN);
    	
    	//assume we are using SHA256, SHA32 returns 32 bytes
    	byte[] enc_psw = new byte[128];
    	
    	//r part of r|h(r,psw)
    	System.arraycopy(salt,0,enc_psw,0,salt.length);
    	
    	//h(r|password) part 
    	byte[] salt_concat_psw = new byte[salt.length + password.length()];
    	System.arraycopy(salt, 0, salt_concat_psw, 0, salt.length);
    	System.arraycopy(password.getBytes(),0,salt_concat_psw,salt.length,password.length());
    	
    	byte[] hashed_salt_concat_psw = hash_SHA256(salt_concat_psw);
    	System.arraycopy(hashed_salt_concat_psw,0, enc_psw,salt.length,hashed_salt_concat_psw.length);    	
    	
    	//first section, 128 bytes
    	System.arraycopy(enc_psw,0,toWrite,0,enc_psw.length);
    	
    	//-------------------------
    	//2. write username
    	//explicit
    	//-------------------------
    	ptr = OFFSET_USERNAME;
    	int tp = ptr;//temporary pointer
    	System.arraycopy(user_name.getBytes(),0,toWrite,tp,user_name.length());
    	
    	//padding this section to 128 bytes
    	if(128 - user_name.length() > 0)
    	{
    		tp += user_name.length();
    		for(;tp < 128 + 128;tp++)
    			toWrite[tp] = DELIMITTER; 		
    	}
    	
    	//----------------------
    	//3. write file length
    	//----------------------
    	byte[] key_encrypt_length = hash_SHA256(password.getBytes());
    	overwriteLength(toWrite, 0, key_encrypt_length);
    	
    	//------------------------------------
    	//4. write message body start position
    	//------------------------------------
    	byte[] key_encrypt_sp = hash_SHA256(hash_SHA256(password.getBytes()));
    	overWriteStartPos(toWrite, key_encrypt_sp);    	
    	
    	//-----------------------
    	//5. generate and write FEK
    	//encrypted
    	//-----------------------
    	byte[] key_encrypt_fek = hash_SHA256(hash_SHA256(hash_SHA256(password.getBytes())));
    	overwriteFEK(toWrite, key_encrypt_fek);    
    	
    	//-----------
    	//6. write IV
    	//explicit
    	//-----------
    	overwriteIV(toWrite);    	
    	
    	//write bytes to binary files
    	dir = new File(file_name);   	
    	dir.mkdirs();
    	
    	//write meta block
    	writeBlock(file_name,toWrite, META_INDEX);
    	
    	//write HMAC file for meta
    	updateMacBlocks(file_name,  -1, true, password);
    }

    @Override
    public String findUser(String file_name) throws Exception {
    	//read first two sections of meta file 	
    	byte[] toRead = new byte[OFFSET_USERNAME + 128];
    	try{
	    	FileInputStream fis = new FileInputStream(file_name + "/0");
	    	fis.read(toRead);
	    	fis.close();
    	}catch(Exception e){
    		throw new UnsupportedOperationException("Meta file reading exception");
    	}
    	
    	//read the username section
    	byte[] section = new byte[128];
    	int ptr = OFFSET_USERNAME;
    	System.arraycopy(toRead, ptr, section, 0, section.length);
    	
    	int pos = 0;
    	while(pos < section.length){
    		if(section[pos] == DELIMITTER)
    			break;
    		pos ++;
    	}
    	if(pos == 128)
    		return byteArray2String(section);
    	else
    	{
    		byte[] username = new byte[pos];
    		System.arraycopy(section, 0, username, 0, username.length);
    		return byteArray2String(username);
    	}
    }

    private void overwriteLength(byte[] toWrite, int len, byte[] key) throws Exception{
    	
    	int ptr = OFFSET_LENGTH;
    	byte[] len2bytes = ByteBuffer.allocate(4).putInt(len).array();
    	byte[] length = new byte[128];
    	System.arraycopy(len2bytes, 0, length, 0, len2bytes.length);
    	
    	//padding to 128 bytes block
    	byte[] padding_length = new byte[128 - len2bytes.length];
    	(new SecureRandom()).nextBytes(padding_length);
    	System.arraycopy(padding_length, 0, length, 4, padding_length.length);
    	
    	//encrypt file length
    	byte[] encrypted_length = encript_AES_256(length, key);
    	System.arraycopy(encrypted_length, 0, toWrite, ptr, encrypted_length.length);
    }
    
    @Override
    public int length(String file_name, String password) throws Exception {
    	//read password section and verify
    	if(!matchPwd(password,file_name))
    		throw new PasswordIncorrectException();
    	
    	//read first three sections of meta file
    	byte[] toRead = new byte[OFFSET_LENGTH + 128];
    	try{
    		FileInputStream fis = new FileInputStream(file_name + "/0");
    		fis.read(toRead);
    		fis.close();
    	}catch(Exception e){
    		throw new UnsupportedOperationException("Meta file reading exception");
    	}
    	
    	//read length section
    	byte[] section = new byte[128];
    	int ptr = OFFSET_LENGTH;//start of length section
    	System.arraycopy(toRead, ptr, section, 0, section.length);
    	
    	//decrypt length
    	byte[] key_encrypt_length = hash_SHA256(password.getBytes());
    	byte[] decrypted_section = decript_AES_256(section,key_encrypt_length);
    	
        int length =  ByteBuffer.wrap(decrypted_section).getInt();
        return length;
    }

    @Override
    public byte[] read(String file_name, int starting_position, int len, String password) throws Exception {
    	//read password section and verify
    	if(!matchPwd(password,file_name))
    		throw new PasswordIncorrectException();
        
    	if(length(file_name,password) == 0)
    		return (new byte[0]);
    	
    	else{
    		//Note: content_start_pos is where front padding ends, where content starts
    		int content_start_pos = getStartPos(file_name, password);
    		int content_length = length(file_name,password);
    		int iv = getIV(file_name, password);
    		byte[] key_encrypt_fek = hash_SHA256(hash_SHA256(hash_SHA256(password.getBytes())));
    		byte[] fek = getFEK(file_name, key_encrypt_fek, password);
    		
    		
    		if(starting_position + len > content_length)
    			throw new UnsupportedOperationException("Read array index outbound exception");
    		
    		// compute the physical index number of the last block
    		int startBlock = (content_start_pos + starting_position)/Config.BLOCK_SIZE;
    		int endBlock = (content_start_pos + starting_position + len)/Config.BLOCK_SIZE;
    		
    		byte[] padded_content = new byte[(endBlock - startBlock + 1) * Config.BLOCK_SIZE];
    		
  
        	for(int i = startBlock; i <= endBlock; i++){
        		int physical_index_for_i = calcFileBlockIndex(i, false);
        		byte[] block = readBlock(file_name,physical_index_for_i);
        		System.arraycopy(block, 0, padded_content, (i - startBlock)* Config.BLOCK_SIZE, block.length);
        	}
        	
        	//decrypt padded_content
        	byte[] decrypted_content = ctr_decrypt(file_name, padded_content, 0, padded_content.length, iv + startBlock, fek);
        	
        	byte[] result = new byte[len];
        	System.arraycopy(decrypted_content, starting_position + content_start_pos - startBlock*Config.BLOCK_SIZE, result, 0, result.length);
    		
    		return result;
    	}
    	
    }

    @Override
    public void write(String file_name, int starting_position, byte[] content, String password) throws Exception {
    	//read password section and verify
    	if(!matchPwd(password,file_name))
    		throw new PasswordIncorrectException();
    	
    	int msg_start_pos = getStartPos(file_name,password);
    	
    	//If the content is inseted at some place in the first block, regenerate everything except fek
    	if(msg_start_pos + starting_position < Config.BLOCK_SIZE){
    		//original length and content
    		int orn_len = length(file_name,password);
    		byte[] orn_content = read(file_name,0,orn_len,password);
    		
    		if(starting_position > orn_len)
    			throw new UnsupportedOperationException("write position out of bound");
    		
        	//-------------------------------------
        	// Update Meta Part
        	//------------------------------------- 
        	byte[] meta = readBlock(file_name,META_INDEX);
        	
        	//write updated random sp
        	byte[] key_encrypt_sp = hash_SHA256(hash_SHA256(password.getBytes()));
    		overWriteStartPos(meta,key_encrypt_sp);
    		
    		//write updated length
    		byte[] key_encrypt_length = hash_SHA256(password.getBytes());
    		overwriteLength(meta, orn_content.length + content.length, key_encrypt_length);
    		
    		//update meta file
    		writeBlock(file_name, meta, META_INDEX);
        	
        	//update the MAC file for meta block
        	updateMacBlocks(file_name, -1, true, password);
        	
        	//-------------------------------------
        	// Then Update Content Part
        	//-------------------------------------    		
        	byte[] upd_content = new byte[orn_content.length + content.length];
    		System.arraycopy(orn_content, 0, upd_content, 0, starting_position);
    		System.arraycopy(content, 0, upd_content, starting_position, content.length);
    		System.arraycopy(orn_content,starting_position,upd_content,starting_position + content.length,orn_content.length-starting_position);
    		    		
    		//encrypt the file with CTR
    		int iv = getIV(file_name, password);
    		byte[] key_encrypt_fek = hash_SHA256(hash_SHA256(hash_SHA256(password.getBytes())));
    		byte[] fek = getFEK(file_name,key_encrypt_fek, password);
    		
    		msg_start_pos = getStartPos(file_name,password);
    		byte[] encrypted_upd_content = ctr_encrypt(file_name, upd_content, msg_start_pos, iv, fek);
    		
    		//write to disk
    		writeContentToDisk(file_name, encrypted_upd_content,0, password);
    		
    		//update MAC blocks from the first content block
    		updateMacBlocks(file_name,  0, false, password);
    	}
    	else
    	{
        	/*
        	 * otherwise, only update from starting_position onwards 
        	 */
    		int orn_len = length(file_name,password);
 		
    		if(starting_position > orn_len)
    			throw new UnsupportedOperationException("write position out of bound");
    		
        	//-------------------------------------
        	// Update Meta Part
        	//------------------------------------- 
        	byte[] meta = readBlock(file_name, META_INDEX);
        	
    		//write updated length
    		byte[] key_encrypt_length = hash_SHA256(password.getBytes());
    		overwriteLength(meta, orn_len + content.length, key_encrypt_length);
    		
    		//update meta file
        	writeBlock(file_name, meta, META_INDEX);
        	
        	//update the MAC file for meta file
        	updateMacBlocks(file_name,  -1, true, password);
        	
        	//-------------------------------------
        	// Then Update Content Part
        	//-------------------------------------        	
        	msg_start_pos = getStartPos(file_name,password);  
        	int ptr_update_from = (msg_start_pos + starting_position)/(Config.BLOCK_SIZE) * Config.BLOCK_SIZE;
        	int actualBlock = ptr_update_from/Config.BLOCK_SIZE;
        	
        	byte[] front_padding_on_that_block = read(file_name,ptr_update_from,msg_start_pos + starting_position - ptr_update_from, password);
        	byte[] orn_content = read(file_name,starting_position,orn_len - starting_position,password);
        	
        	byte[] upd_content;
        	if((orn_content.length + front_padding_on_that_block.length + content.length) % Config.BLOCK_SIZE == 0)
        		upd_content = new byte[orn_content.length + front_padding_on_that_block.length + content.length];
        	else
        		upd_content = new byte[((orn_content.length + front_padding_on_that_block.length + content.length) / Config.BLOCK_SIZE + 1) * Config.BLOCK_SIZE];
    		
        	System.arraycopy(front_padding_on_that_block, 0, upd_content, 0, front_padding_on_that_block.length);
    		System.arraycopy(content, 0, upd_content, front_padding_on_that_block.length, content.length);
    		System.arraycopy(orn_content,0,upd_content,front_padding_on_that_block.length + content.length,orn_content.length);
    		
    		byte[] padding_upd_content = new byte[upd_content.length - (orn_content.length + front_padding_on_that_block.length + content.length)];
    		(new SecureRandom()).nextBytes(padding_upd_content);
    		System.arraycopy(padding_upd_content, 0, upd_content, orn_content.length + front_padding_on_that_block.length + content.length, padding_upd_content.length);
    		
    		//encrypt the file with CTR
    		int iv = getIV(file_name, password);
    		byte[] key_encrypt_fek = hash_SHA256(hash_SHA256(hash_SHA256(password.getBytes())));
    		byte[] fek = getFEK(file_name,key_encrypt_fek, password);
    		
    		//here msg_start_pos is 0, since we are only updating blocks from the changing point
    		byte[] encrypted_upd_content = ctr_encrypt(file_name, upd_content, 0, iv + actualBlock, fek);
    		
    		//write to disk
    		writeContentToDisk(file_name, encrypted_upd_content,actualBlock, password);
    		
    		//update mac from the changing point
    		updateMacBlocks(file_name, actualBlock, false, password);
    		
    	}
    	
    }
    
    /**
     * This method pads random bytes before and after body message, and then encrypts the entire array
     * @param file_name
     * @param content
     * @param start_pos: the index body message starts (after front paddings)
     * @param iv
     * @param fek
     * @return
     * @throws Exception
     */
    private byte[] ctr_encrypt(String file_name, byte[] content, int start_pos, int iv, byte[] fek) throws Exception{
    	
    	byte[] padded_content;
    	if((start_pos + content.length) % Config.BLOCK_SIZE == 0)
    		padded_content = new byte[start_pos + content.length];
    	else
    		padded_content = new byte[Config.BLOCK_SIZE * (1+ (start_pos + content.length)/Config.BLOCK_SIZE)];
    	
    	//pad random bytes before and after content
    	byte[] front_padding = new byte[start_pos];
    	(new SecureRandom()).nextBytes(front_padding);
    	System.arraycopy(front_padding, 0, padded_content, 0, front_padding.length);
    	
    	System.arraycopy(content,0,padded_content,front_padding.length,content.length);
    	
    	byte[] back_padding = new byte[padded_content.length - content.length - start_pos];
    	(new SecureRandom()).nextBytes(back_padding);
    	System.arraycopy(back_padding, 0, padded_content, front_padding.length + content.length, back_padding.length);
    	
    	//encrypt padded content
    	byte[] encrypted_padded_content = new byte[padded_content.length];
    	int blocks_AES = encrypted_padded_content.length/(AES_BLOCK_SIZE/8);
    	
    	//encrypt the plain text with AES CTR
    	byte[] counter = new byte[AES_BLOCK_SIZE/8];
    	byte[] encrypted_counter;
    	
    	for(int i = 1; i <= blocks_AES; i++){
    		
    		byte[] counter2bytes = ByteBuffer.allocate(4).putInt(iv+i).array();
    		System.arraycopy(counter2bytes,0,counter,0,counter2bytes.length);
    		encrypted_counter = encript_AES(counter, fek);
    		
    		byte[] mi = new byte[AES_BLOCK_SIZE/8];
    		System.arraycopy(padded_content, (i-1)*(AES_BLOCK_SIZE/8), mi, 0, mi.length);
    		
    		//perform xor for mi and ek(iv + 1)
    		BitSet bs_ci = BitSet.valueOf(mi);
    		bs_ci.xor(BitSet.valueOf(encrypted_counter));
    		byte[] ci = bs_ci.toByteArray();
    		System.arraycopy(ci, 0, encrypted_padded_content, (i-1)*(AES_BLOCK_SIZE/8), ci.length);
    	}
    	
    	return encrypted_padded_content;    	
    }
    
    /**
     * This method decrypts content array (padded before and after) and return the body message (excluding random paddings)
     * @param file_name
     * @param encrypted_content
     * @param start_pos: where front padding ends, where content starts
     * @param iv
     * @param fek
     * @return
     */
    private byte[] ctr_decrypt(String file_name, byte[] encrypted_content, int start_pos, int length, int iv, byte[] fek) throws Exception{
    	
    	if(start_pos + length > encrypted_content.length)
    		throw new UnsupportedOperationException("decrypt array outbound exception");
    	
    	byte[] decrypted_content = new byte[encrypted_content.length];
    	int blocks_AES = decrypted_content.length/(AES_BLOCK_SIZE/8);
    	
    	//decrypt the plain text with AES CTR
    	byte[] counter = new byte[AES_BLOCK_SIZE/8];
    	byte[] encrypted_counter;
    	
    	for(int i = 1; i <= blocks_AES; i++){
    		
    		byte[] counter2bytes = ByteBuffer.allocate(4).putInt(iv+i).array();
    		System.arraycopy(counter2bytes,0,counter,0,counter2bytes.length);
    		encrypted_counter = encript_AES(counter, fek);
    		
    		byte[] ci = new byte[AES_BLOCK_SIZE/8];
    		System.arraycopy(encrypted_content, (i-1)*(AES_BLOCK_SIZE/8), ci, 0, ci.length);
    		
    		//perform xor for ci and ek(iv + i)
    		BitSet bs_mi = BitSet.valueOf(ci);
    		bs_mi.xor(BitSet.valueOf(encrypted_counter));
    		byte[] mi = bs_mi.toByteArray();
    		System.arraycopy(mi, 0, decrypted_content, (i-1)*(AES_BLOCK_SIZE/8), mi.length);
    	}
    	
    	//remove random padding in front and after content
    	byte[] content = new byte[length];
    	System.arraycopy(decrypted_content, start_pos, content, 0, length);
    	
    	return content;
    }

    @Override
    public boolean check_integrity(String file_name, String password) throws Exception {  	
    	//read password section and verify
    	if(!matchPwd(password,file_name))
    		throw new PasswordIncorrectException();
    	
    	//check integrity for meta
    	byte[] meta = readBlock(file_name, 0);
    	
    	byte[] mac_for_meta = hMac(meta, password);
    	
    	byte[] mac_block_for_meta = readBlock(file_name, META_MAC_INDEX);
    	
    	byte[] stored_mac_for_meta = new byte[32];
    	System.arraycopy(mac_block_for_meta, 0, stored_mac_for_meta, 0, stored_mac_for_meta.length);
    	
    	//integrity checking fails for meta block
    	if(!Arrays.equals(mac_for_meta, stored_mac_for_meta))
    		return false;
    	
    	//check the zero paddings for the remaining part of meta mac
    	for(int i = stored_mac_for_meta.length; i < Config.BLOCK_SIZE; i++){
    		if(mac_block_for_meta[i] != (byte) 0)
    			return false;
    	} 	
    	    	
    	//chekck integrity for content
    	int length = length(file_name, password);
    	int msg_start_pos = getStartPos(file_name, password);
    	
    	//number of blocks containing content, excluding meta and mac
    	int totalActualBlocks;
    	if((length + msg_start_pos) % Config.BLOCK_SIZE ==0 )
    		totalActualBlocks = (length + msg_start_pos) / Config.BLOCK_SIZE;
    	else
    		totalActualBlocks = (length + msg_start_pos) / Config.BLOCK_SIZE + 1; 
    	
    	//number of block group
    	int totalGroups;
    	if(totalActualBlocks % (Config.BLOCK_SIZE / 32) == 0)
    		totalGroups = totalActualBlocks/(Config.BLOCK_SIZE/32);
    	else
    		totalGroups = totalActualBlocks/(Config.BLOCK_SIZE/32) + 1;
    	
    	//check the number of blocks for a file is correct or not
    	File dir = new File(file_name);
    	File[] files = dir.listFiles();
    	if(files.length != 2 + totalActualBlocks + totalGroups)
    		return false;
    	
    	//for each group of blocks, check the integrity for each block
    	for(int i = 0; i < totalGroups; i++){
    		int physicalIndexForMac = 2 + i*(Config.BLOCK_SIZE/32 + 1);
    		byte[] mac = readBlock(file_name, physicalIndexForMac);
    		
    		for(int j = 0; j < Config.BLOCK_SIZE/32; j ++){
    			//jth block in group i
    			int actualBlock = i * (Config.BLOCK_SIZE/32) + j;
    			if (actualBlock >= totalActualBlocks)
    				break;
    			int physicalBlock = calcFileBlockIndex(actualBlock, false);
    			byte[] block = readBlock(file_name,physicalBlock);
    			byte[] mac_for_block = hMac(block, password);
    			
    			byte[] stored_mac = new byte[32];
    			System.arraycopy(mac, j*32, stored_mac, 0, stored_mac.length);
    			
    			if(!Arrays.equals(mac_for_block, stored_mac))
    					return false;
    		}
    	}
    	
    	//verify the zero paddings for last mac block
    	int temp =2 + (totalGroups - 1)* (Config.BLOCK_SIZE/32 + 1);
    	byte[] last_mac = readBlock(file_name, temp);
    	int padding_start = 32 * (totalActualBlocks % (Config.BLOCK_SIZE/32));
    	System.out.println(2 + (totalGroups - 1)* (Config.BLOCK_SIZE + 1));
    	for(int i = padding_start; i < last_mac.length; i++){
    		if(last_mac[i] != (byte) 0)
    			return false;
    	} 	
    	
    	return true;   	
    }

    @Override
    public void cut(String file_name, int length, String password) throws Exception {
    
    	//read password section and verify
    	if(!matchPwd(password,file_name))
    		throw new PasswordIncorrectException();
    	
    	
    	int orn_length= length(file_name, password);
    	
    	//if the specified cut length is longer than that of original content, do nothing
    	if(length > orn_length)
    		return;
    	
    	//update length in meta file
    	byte[] meta = readBlock(file_name, META_INDEX);
    	byte[] key_encrypt_length = hash_SHA256(password.getBytes());
    	overwriteLength(meta, length, key_encrypt_length);
    	writeBlock(file_name, meta, META_INDEX);
    	
    	//write HMAC file for meta
    	updateMacBlocks(file_name,  -1, true, password);
    	
    	//remove redundant blocks
    	removeRedundantBlocks(file_name, password);
    	        
    }
    

    

    
    // regenerate and write message body start position
    // toWrite is the byte array for meta file
    // return byte array after overwriting
    private void overWriteStartPos(byte[] toWrite, byte[] key) throws Exception{
    	
    	int ptr = OFFSET_START_POS;
    	int sp =(int) ((new SecureRandom()).nextDouble() * Config.BLOCK_SIZE);
    	byte[] sp2bytes = ByteBuffer.allocate(4).putInt(sp).array();
    	byte[] start_pos = new byte[128];
    	System.arraycopy(sp2bytes, 0, start_pos, 0, sp2bytes.length);
    	
    	//padding to 128 bytes block
    	byte[] padding_sp = new byte[128 - 4];
    	(new SecureRandom()).nextBytes(padding_sp);
    	System.arraycopy(padding_sp, 0, start_pos, sp2bytes.length, padding_sp.length);
    	
    	//encrypt start position
    	byte[] encrypted_start_pos = encript_AES_256(start_pos, key);
    	System.arraycopy(encrypted_start_pos, 0, toWrite, ptr, start_pos.length);
    }
    

    private int getStartPos(String file_name, String password) throws Exception {
    	//read password section and verify
    	if(!matchPwd(password,file_name))
    		throw new PasswordIncorrectException();
    	
    	//read first three sections of meta file
    	byte[] toRead = new byte[OFFSET_START_POS + 128];
    	try{
    		FileInputStream fis = new FileInputStream(file_name + "/0");
    		fis.read(toRead);
    		fis.close();
    	}catch(Exception e){
    		throw new UnsupportedOperationException("Meta file reading exception");
    	}
    	
    	//read length section
    	byte[] section = new byte[128];
    	int ptr = OFFSET_START_POS;//start of length section
    	System.arraycopy(toRead, ptr, section, 0, section.length);
    	
    	//decrypt length
    	byte[] key_encrypt_sp = hash_SHA256(hash_SHA256(password.getBytes()));
    	byte[] decrypted_section = decript_AES_256(section, key_encrypt_sp);
    	
        int length =  ByteBuffer.wrap(decrypted_section).getInt();
        return length;
    }
    
    //regenerate a new iv number, and update file buffer
    //toWrite is the output
    private void overwriteIV(byte[] toWrite){//iv explicit
    	
    	int ptr = OFFSET_IV;
    	int iv = (new SecureRandom()).nextInt();;
    	byte[] iv2bytes = ByteBuffer.allocate(4).putInt(iv).array();
    	
    	System.arraycopy(iv2bytes, 0, toWrite, ptr, iv2bytes.length);
    }
    
    private int getIV(String file_name, String password) throws Exception{
    	//read password section and verify
    	if(!matchPwd(password,file_name))
    		throw new PasswordIncorrectException();
    	
    	//read sections on and before iv of meta file
    	byte[] toRead = new byte[OFFSET_IV + 128];
    	try{
    		FileInputStream fis = new FileInputStream(file_name + "/0");
    		fis.read(toRead);
    		fis.close();
    	}catch(Exception e){
    		throw new UnsupportedOperationException("Meta file reading exception");
    	}
    	
    	byte[] iv2bytes = new byte[4];
    	System.arraycopy(toRead, OFFSET_IV, iv2bytes, 0, iv2bytes.length);
    	
    	int iv = ByteBuffer.wrap(iv2bytes).getInt();
    	
    	return iv;
    }
    
    private void overwriteFEK(byte[] toWrite, byte[] key) throws Exception{
    	
    	int ptr = OFFSET_FEK;
    	byte[] fek_section = new byte[128];
    	
    	byte[] fek = (new SecureRandom()).generateSeed(AES_BLOCK_SIZE/8);    	
    	System.arraycopy(fek, 0, fek_section, 0, fek.length);
    	
    	byte[] fek_padding = new byte[128 - AES_BLOCK_SIZE/8];
    	System.arraycopy(fek_padding, 0, fek_section, fek.length, fek_padding.length);
    	
    	//encrypt fek

    	byte[] encrypted_fek_section = encript_AES_256(fek_section,key);
    	System.arraycopy(encrypted_fek_section, 0, toWrite, ptr, encrypted_fek_section.length);
    }
    
    private byte[] getFEK(String file_name, byte[] key, String password) throws Exception{
    	//read password section and verify
    	if(!matchPwd(password,file_name))
    		throw new PasswordIncorrectException();
    	
    	//read sections on and before fek of meta file
    	byte[] toRead = new byte[OFFSET_FEK + 128];
    	try{
    		FileInputStream fis = new FileInputStream(file_name + "/0");
    		fis.read(toRead);
    		fis.close();
    	}catch(Exception e){
    		throw new UnsupportedOperationException("Meta file reading exception");
    	}
    	byte[] section = new byte[128];
    	System.arraycopy(toRead, OFFSET_FEK, section, 0, section.length);
    	byte[] decripted_section = decript_AES_256(section,key);
    	
    	
    	byte[] fek = new byte[AES_BLOCK_SIZE/8];
    	System.arraycopy(decripted_section, 0, fek, 0, fek.length);
    	
    	return fek;
    }
    
    //content already includes front and back paddings
    private void writeContentToDisk(String file_name, byte[] content, int actualStartBlockIndex, String password) throws Exception{

    	if(content.length % Config.BLOCK_SIZE != 0)
    		throw new UnsupportedOperationException("input array length for writeContent is not valid");
    	
    	//Write content blocks
    	int blocks_num = content.length / Config.BLOCK_SIZE;
    	byte[] block = new byte[Config.BLOCK_SIZE];
    	  	
    	for(int i = 0; i < blocks_num; i++){
    		
    		System.arraycopy(content, i*Config.BLOCK_SIZE, block, 0, block.length);	
    		
    		//write each block, each 256 hash ouput takes 32 bytes
    		int file_physical_index = calcFileBlockIndex(i + actualStartBlockIndex, false);
    		writeBlock(file_name, block, file_physical_index);
    	}
    	
    	//Update MAC block for each group
    	updateMacBlocks(file_name, actualStartBlockIndex, false, password);
    	
    	//remove redundant blocks file behind
    	removeRedundantBlocks(file_name, password);
    }
    
    
    private byte[] hMac(byte[] msg, String password) throws Exception{
    	int width = 16;
    	byte[] key = password.getBytes();
    	//key padded by byte 0x36
    	byte[] key_ipad = new byte[width];
    	Arrays.fill(key_ipad, (byte) 0x36);
    	if(key.length <= key_ipad.length)
    		System.arraycopy(key, 0, key_ipad, 0, key.length);
    	else
    		System.arraycopy(key, 0, key_ipad, 0, key_ipad.length);
    	
    	//key padded by byte 0x5C
    	byte[] key_opad = new byte[width];
    	Arrays.fill(key_opad, (byte) 0x5C);
    	if(key.length <= key_opad.length)
    		System.arraycopy(key, 0, key_opad, 0, key.length);
    	else
    		System.arraycopy(key,0,key_opad,0,key_opad.length);
    	
    	byte[] ipad_concat_msg = new byte[key_ipad.length + msg.length];
    	System.arraycopy(key_ipad, 0, ipad_concat_msg, 0, key_ipad.length);
    	System.arraycopy(msg,0,ipad_concat_msg,key_ipad.length,msg.length);
    	
    	byte[] hash1 = hash_SHA256(ipad_concat_msg);
    	byte[] opad_concat_hash1 = new byte[key_opad.length + hash1.length];
    	System.arraycopy(key_opad,0,opad_concat_hash1,0,key_opad.length);
    	System.arraycopy(hash1, 0, opad_concat_hash1, key_opad.length, hash1.length);
    	
    	return hash_SHA256(opad_concat_hash1);
    	
    }
    
    /**
     * If blocks are updated, relevant MAC blocks need to be updated
     * @param file_name
     * @param password
     * @param startOfActualBlockIndex
     * @param isMeta
     * @throws Exception
     */
    private void updateMacBlocks(String file_name, int startOfActualBlockIndex, boolean isMeta, String password) throws Exception{
    	
    	if(isMeta == true){
    		byte[] meta = readBlock(file_name, META_INDEX);
        	byte[] mac_for_meta = hMac(meta,password);
        	byte[] mac_for_meta_block = new byte[Config.BLOCK_SIZE];
        	System.arraycopy(mac_for_meta, 0, mac_for_meta_block, 0, mac_for_meta.length);
        	writeBlock(file_name, mac_for_meta_block,META_MAC_INDEX);
        	return;
    	}else{
    		
    		int length = length(file_name, password);
    		int start_pos = getStartPos(file_name, password);
    		int total_block_number;
    		if((length + start_pos) % Config.BLOCK_SIZE == 0)
    			total_block_number = (length + start_pos) / Config.BLOCK_SIZE;
    		else
    			total_block_number = (length + start_pos) / Config.BLOCK_SIZE + 1;
        	
    		int blocks_to_update = total_block_number - startOfActualBlockIndex;
        	byte[] block = new byte[Config.BLOCK_SIZE];
        	byte[] hmac_block = new byte[Config.BLOCK_SIZE];
        	
        	//it means the start block is not the first block of its group
        	if(startOfActualBlockIndex % (Config.BLOCK_SIZE/32) != 0){
        		int physicalMacIndex = calcFileBlockIndex(startOfActualBlockIndex, true);
        		hmac_block = readBlock(file_name,physicalMacIndex);
        	}
        	
        	for(int i = 0; i < blocks_to_update; i++){
        		//flush hash block for each new group
        		if((i + startOfActualBlockIndex) % (Config.BLOCK_SIZE/32) == 0)
        			Arrays.fill(hmac_block,(byte)0);
        		
        		int physical_index_for_i = calcFileBlockIndex(i + startOfActualBlockIndex, false);
        		block = readBlock(file_name, physical_index_for_i);
            	
            	//compute hmac for each group of blocks
            	byte[] hmac_for_block_i = hMac(block,password);
            	System.arraycopy(hmac_for_block_i, 0, hmac_block, (i + startOfActualBlockIndex)%(Config.BLOCK_SIZE/32)*hmac_for_block_i.length, hmac_for_block_i.length);
            	      	
            	//write mac block for each group, when the last block for that group is computed
            	if((i+ startOfActualBlockIndex) %(Config.BLOCK_SIZE/32) == Config.BLOCK_SIZE/32 -1 
            			|| i == blocks_to_update - 1)
            		writeBlock(file_name, hmac_block, calcFileBlockIndex(i + startOfActualBlockIndex,true));
        	}       	   		
    	}
    }
    
    private void removeRedundantBlocks(String file_name, String password) throws Exception{
    	
    	int length = length(file_name, password);
    	int start_pos = getStartPos(file_name, password);
    	int total_content_blocks;
    	if((length + start_pos) % Config.BLOCK_SIZE == 0)
    		total_content_blocks = (length + start_pos)/Config.BLOCK_SIZE;
    	else
    		total_content_blocks = (length + start_pos)/Config.BLOCK_SIZE + 1;
    	
    	int total_groups;
    	if(total_content_blocks%(Config.BLOCK_SIZE/32) == 0)
    		total_groups = total_content_blocks/(Config.BLOCK_SIZE / 32);
    	else
    		total_groups = total_content_blocks/(Config.BLOCK_SIZE / 32) + 1;
    	
    	int last_physical_block_index = 1 + total_content_blocks + total_groups;
    	
    	//remove blocks from the last physical block
    	File dir = new File(file_name);
    	File[] files = dir.listFiles();
    	
    	if(files.length > last_physical_block_index + 1){
    		for(int i = 0; i < files.length; i++){
    			
    			try{
    				int node_index = Integer.parseInt(files[i].getName());
    				if(node_index > last_physical_block_index){
    					files[i].delete();
    				}
    			}catch(NumberFormatException  e){
    				//remove files with incorrect names
    				files[i].delete();
    			}catch(Exception e){
    				//ignore
    			}
    			
    		}
    	}
    }
    
    //-----------------------
    //helper functions
    //-----------------------

    /**
     * Since we are not allowed to use key with more than 128 bits with default Java cipher
     * We implement an encryption which can take in 256 bits key ourselves
     * @param plainText
     * @param key
     * @return ciphertext array
     * @throws Exception
     */
    private static byte[] encript_AES_256(byte[] plainText, byte[] key) throws Exception {
    	
    	if(key.length != 32)
    		throw new UnsupportedOperationException("key length not 256 bits");
    	
    	byte[] key1 = new byte[key.length/2];
    	byte[] key2 = new byte[key.length/2];
    	System.arraycopy(key, 0, key1, 0, key1.length);
    	System.arraycopy(key, key1.length, key2, 0, key2.length);
    	
    	byte[] plainText1 = new byte[plainText.length/2];
    	byte[] plainText2 = new byte[plainText.length/2];
    	
    	int blocks = plainText.length/key.length;
    	for(int i =0; i < blocks; i++){
    		System.arraycopy(plainText, i*key.length, plainText1, i*key1.length, key1.length);
    		System.arraycopy(plainText, i*key.length + key1.length, plainText2, i*key2.length, key2.length);
    	}
    	
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");

        SecretKeySpec secretKey = new SecretKeySpec(key1, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] ciphertext1 = cipher.doFinal(plainText1);
        
        secretKey = new SecretKeySpec(key2,"AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] ciphertext2 = cipher.doFinal(plainText2);
        
        byte[] ciphertext = new byte[plainText.length];
        
        for(int i = 0; i < blocks; i++){
        	System.arraycopy(ciphertext1, i*key1.length, ciphertext, i*key.length, key1.length);
        	System.arraycopy(ciphertext2, i*key2.length, ciphertext, i*key.length+key1.length, key2.length);
        }

        return ciphertext;
    }
    
    /**
     * @param cypherText
     * @param key
     * @return Plaint text array
     * @throws Exception
     */
    private static byte[] decript_AES_256(byte[] cypherText, byte[] key) throws Exception {
    	
    	if(key.length != 32)
    		throw new UnsupportedOperationException("key length not 256 bits");
    	
    	byte[] key1 = new byte[key.length/2];
    	byte[] key2 = new byte[key.length/2];
    	System.arraycopy(key, 0, key1, 0, key1.length);
    	System.arraycopy(key, key1.length, key2, 0, key2.length);
    	
    	byte[] cypherText1 = new byte[cypherText.length/2];
    	byte[] cypherText2 = new byte[cypherText.length/2];
    	
    	int blocks = cypherText.length/key.length;
    	for(int i =0; i < blocks; i++){
    		System.arraycopy(cypherText, i*key.length, cypherText1, i*key1.length, key1.length);
    		System.arraycopy(cypherText, i*key.length + key1.length, cypherText2, i*key2.length, key2.length);
    	}
    	
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");

        SecretKeySpec secretKey = new SecretKeySpec(key1, "AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        
        byte[] plainText1 = cipher.doFinal(cypherText1);
        byte[] plainText2 = cipher.doFinal(cypherText2);
        
        byte[] plainText = new byte[cypherText.length];
        
        for(int i = 0; i < blocks; i++){
        	System.arraycopy(plainText1, i*key1.length, plainText, i*key.length, key1.length);
        	System.arraycopy(plainText2, i*key2.length, plainText, i*key.length+key1.length, key2.length);
        }

        return plainText;
    }

    
    /**
     * Calculate the physical file block index given the actual block index  in the content (the actual block index excludes MAC block)
     * If isMacBlock is set true, calculate the physical MAC file block index when the MAC of the actual block is located
     * @param actual_block
     * @param isMacBlock
     * @return
     */
    private static int calcFileBlockIndex(int actual_block, boolean isMacBlock){
    	if(isMacBlock == false)
    		return 3 + actual_block / (Config.BLOCK_SIZE/32) * (Config.BLOCK_SIZE/32 + 1) + actual_block % (Config.BLOCK_SIZE/32);
    	else
    		return 2 + actual_block/(Config.BLOCK_SIZE/32) * (Config.BLOCK_SIZE/32 + 1);
    		
    }
    
    /**
     * Read whole block into a byte array with specified physical block index
     * @param file_name
     * @param physical_block
     * @return
     * @throws Exception
     */
    private static byte[] readBlock(String file_name, int physical_block) throws Exception{
    	
    	

    	//check the file size first
    	File f = new File(file_name + "/" + physical_block);    	
    	if(f.length() != Config.BLOCK_SIZE)
    		throw new UnsupportedOperationException("Block size is not " + Config.BLOCK_SIZE);

    	//read file into byte array
    	byte[] block = new byte[Config.BLOCK_SIZE];
    	try{
    		FileInputStream fis = new FileInputStream(file_name + "/" + physical_block);
    		fis.read(block);
    		fis.close();
    	}catch(Exception e){
    		throw new UnsupportedOperationException("Physical block file reading exception");
    	}  	
    	return block;
    }
    
    /**
     * Write byte array into a block file with index specified
     * @param file_name
     * @param block
     * @param block_index
     * @throws Exception
     */
    private void writeBlock(String file_name, byte[] block, int block_index) throws Exception{
    	
    	if(block.length != Config.BLOCK_SIZE)
    		throw new UnsupportedOperationException("writing lock array size not valid");
    	
    	FileOutputStream fos = new FileOutputStream(file_name + "/" + block_index);
    	fos.write(block);
    	fos.close();
    }
    
    

    /**
     * Takethe password user inputs, and compare with the encrypted one in meta file
     * @param password
     * @param file_name
     * @return
     * @throws Exception
     */
    private static boolean matchPwd(String password, String file_name) throws Exception{
    	//read first section of meta file 	
    	byte[] toRead = new byte[OFFSET_PASSWORD + 128];
    	try{
	    	FileInputStream fis = new FileInputStream(file_name + "/0");
	    	fis.read(toRead);
	    	fis.close();
    	}catch(Exception e){
    		throw new UnsupportedOperationException("Meta file reading exception");
    	}
    	
    	//read the encrypted password section
    	byte[] section = toRead;
    	byte[] salt = new byte[SALT_LEN];
    	System.arraycopy(section, 0, salt, 0, salt.length);
    	
    	//SHA256
    	byte[] hashed_salt_concat_psw = new byte[32];
    	System.arraycopy(section, SALT_LEN, hashed_salt_concat_psw, 0, hashed_salt_concat_psw.length);
    	
    	//generate the hash with salt and input password
    	byte[] salt_concat_psw = new byte[salt.length + password.length()];
    	System.arraycopy(salt,0,salt_concat_psw,0,salt.length);
    	System.arraycopy(password.getBytes(),0,salt_concat_psw,SALT_LEN,password.length());
    	
    	byte[] hashed_input = hash_SHA256(salt_concat_psw);
    	
    	return Arrays.equals(hashed_salt_concat_psw, hashed_input); 	
    }
}
